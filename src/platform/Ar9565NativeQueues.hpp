// SPDX-License-Identifier: GPL-2.0-only
#ifndef SIMPLEATH_AR9565_NATIVE_QUEUES_HPP
#define SIMPLEATH_AR9565_NATIVE_QUEUES_HPP
#include "../hardware/Ar9003TxControl.hpp"
#include "../hardware/Ar9565Core.hpp"
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>

namespace simpleath
{
    struct NativeQueueMemory;

    struct NativeQueueOwner
    {
            void *context;
            bool (*current)(void *, uint64_t epoch);
            bool (*radioReady)(void *, uint64_t epoch);
            bool (*setBusMaster)(void *, bool enabled);
            bool (*read32)(void *, uint32_t offset, uint32_t *value);
            bool (*write32)(void *, uint32_t offset, uint32_t value);
            void (*delayMicros)(void *, uint32_t micros);
            // RX bytes are borrowed only for this synchronous callback. Copy
            // into the native packet pool before returning. TX token belongs to
            // caller.
            void (*receive)(void *, const uint8_t *, size_t,
                            const edma::RxStatus &);
            void (*transmitted)(void *, uint64_t token,
                                const edma::TxCompletion &);
            void (*fault)(void *, IOReturn);
            uint32_t barLengthBytes;
    };
    enum class NativeQueuePhase : uint8_t
    {
        Empty,
        Prepared,
        Running,
        Quarantined,
    };

    class NativeQueues final
    {
        public:
            NativeQueues() = default;
            ~NativeQueues();
            NativeQueues(const NativeQueues &) = delete;
            NativeQueues &operator=(const NativeQueues &) = delete;
            NativeQueues(NativeQueues &&) = delete;
            NativeQueues &operator=(NativeQueues &&) = delete;
            // May block: caller retains its operation and invokes this outside
            // the work loop/gate. Serializes client calls with its lifecycle
            // lock.
            IOReturn
            prepareClient(IOService *owner, IOService *pci, IOWorkLoop *loop,
                          uint64_t epoch, const NativeQueueOwner &callbacks,
                          IOInterruptEventSource::Action interruptAction);
            IOReturn adoptGated(uint64_t currentEpoch);
            IOReturn startGated();
            IOReturn transmitGated(const uint8_t *frame, size_t bytes,
                                   uint64_t token,
                                   const edma::TxControlRequest &control,
                                   const edma::TxSafetyPolicy &policy);
            void serviceInterruptGated();
            // Disable/remove IRQ delivery and stop DMA before BAR teardown.
            // False quarantines mappings; a timeout never makes buffers
            // freeable.
            bool stopGated(bool providerAvailable);
            IOReturn releaseClient();

            NativeQueuePhase phase() const
            {
                return phase_;
            }

            uint64_t epoch() const
            {
                return epoch_;
            }

            bool hasTransmitSpace() const
            {
                return phase_ == NativeQueuePhase::Running && !txPending_;
            }

        private:
            bool gated() const;
            bool read(uint32_t offset, uint32_t &value) const;
            bool write(uint32_t offset, uint32_t value) const;
            void fault(IOReturn result);
            enum class ReceiveStep : uint8_t
            {
                Processed,
                QueueEmpty,
                Stopped,
            };
            ReceiveStep processRxSlot(uint32_t queue);
            void receiveCompleted();
            void transmitCompleted();
            IOService *owner_ {nullptr};
            IOService *pci_ {nullptr};
            IOWorkLoop *loop_ {nullptr};
            IOInterruptEventSource *interrupt_ {nullptr};
            NativeQueueMemory *memory_ {nullptr};
            NativeQueueOwner callbacks_ {};
            NativeQueuePhase phase_ {NativeQueuePhase::Empty};
            uint64_t epoch_ {0};
            uint64_t txToken_ {0};
            uint16_t nextDescriptorId_ {1};
            uint16_t pendingDescriptorId_ {0};
            uint16_t txSlot_ {0};
            uint16_t completionHead_ {0};
            bool attached_ {false};
            bool txPending_ {false};
            uint8_t rxHead_[2] {};
            bool droppedChain_[2] {};
    };
} // namespace simpleath
#endif
