// Copyright:
//   - Copyright © 2026 Alberto Villa Osorno
// SPDX-License-Identifier:
//   - MIT
// Confidential:
//   - false
// License-File:
//   - LICENSE-MIT
// Provenance:
//   - SimpleATH original; independently developed or locally authored
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for tahoe packet path.
// - Must-Not:
//   - Invent hardware readiness, weaken buffer bounds, or assume ABI
//     compatibility.
// - Allows:
//   - Inputs: validated register, protocol, platform, or device state from
//     callers.
//   - Outputs: bounded native transitions, messages, or explicit errors.
//   - Side effects: only the device and kernel operations owned by this module.
// - Split-When:
//   - A separate protocol stage needs independent validation and ownership.
// - Merge-When:
//   - The caller directly owns this narrow contract without reuse.
// - Summary:
//   - Native driver contracts and implementation for tahoe packet path.
// - Description:
//   - Implements or verifies the TahoePacketPath source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for tahoe packet path.

// Member-call labels and queue action count semantics independently inspected
// in the matching Intel 25G332 IOSkywalkFamily and IO80211Family images.
#include "TahoePacketPath.hpp"
#include "SimpleATHTahoeController.hpp"
#include "TahoeInterfaceABI.hpp"
#include <IOKit/IOEventSource.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace
{
    using SubmitAction = unsigned int (*)(OSObject *, OSObject *,
                                          OSObject *const *, unsigned int,
                                          void *);
    using FillAction = unsigned int (*)(OSObject *, OSObject *, OSObject **,
                                        unsigned int, void *);
    extern "C" OSObject *
    skyCreatePool(const char *, OSObject *, unsigned int, const void *) __asm__(
        "__ZN25IOSkywalkPacketBufferPool8withNameEPKcP8OSObjectjPKNS_"
        "11PoolOptionsE");
    extern "C" OSObject *
    skyCreateTx(OSObject *, unsigned int, unsigned int, OSObject *,
                SubmitAction, void *,
                unsigned int) __asm__("__"
                                      "ZN26IOSkywalkTxSubmissionQueue8withPoolE"
                                      "P25IOSkywalkPacketBufferPooljjP8OSObject"
                                      "PFjS3_PS_PKP15IOSkywalkPacketjPvES9_j");
    extern "C" OSObject *skyCreateTxCompletion(
        OSObject *, unsigned int, unsigned int, OSObject *, FillAction, void *,
        unsigned int) __asm__("__"
                              "ZN26IOSkywalkTxCompletionQueue8withPoolEP25IOSky"
                              "walkPacketBufferPooljjP8OSObjectPFjS3_PS_"
                              "PP15IOSkywalkPacketjPvES8_j");
    extern "C" OSObject *skyCreateRxCompletion(
        OSObject *, unsigned int, unsigned int, OSObject *, FillAction, void *,
        unsigned int) __asm__("__"
                              "ZN26IOSkywalkRxCompletionQueue8withPoolEP25IOSky"
                              "walkPacketBufferPooljjP8OSObjectPFjS3_PS_"
                              "PP15IOSkywalkPacketjPvES8_j");
    extern "C" bool skyRegistration(
        IO80211SkywalkInterface *, void *, unsigned int,
        unsigned long) __asm__("__"
                               "ZN26IOSkywalkEthernetInterface20initRegistratio"
                               "nInfoEPNS_16RegistrationInfoEjm");
    extern "C" IOReturn skyRegister(
        IO80211SkywalkInterface *, void *, OSObject **, unsigned int,
        OSObject *,
        OSObject
            *) __asm__("__"
                       "ZN21IO80211InfraInterface30registerInfraEthernetInterfa"
                       "ceEPN26IOSkywalkEthernetInterface16RegistrationInfoEPP2"
                       "0IOSkywalkPacketQueuejP25IOSkywalkPacketBufferPoolS7_");
    extern "C" void
    skyDeregister(IO80211SkywalkInterface *, unsigned int) __asm__(
        "__ZN26IOSkywalkEthernetInterface27deregisterEthernetInterfaceEj");
    extern "C" IOReturn
    skyAllocate(OSObject *, OSObject **, unsigned int) __asm__(
        "__ZN25IOSkywalkPacketBufferPool14allocatePacketEPP15IOSkywalkPacketj");
    extern "C" IOReturn
    skyPrepare(OSObject *, OSObject *, unsigned int, unsigned int) __asm__(
        "__ZN15IOSkywalkPacket16prepareWithQueueEP20IOSkywalkPacketQueuejj");
    extern "C" IOReturn
    skyCompletePacket(OSObject *, OSObject *, unsigned int,
                      unsigned int) __asm__("__"
                                            "ZN15IOSkywalkPacket17completeWithQ"
                                            "ueueEP20IOSkywalkPacketQueuejj");
    extern "C" void skyDeallocate(OSObject *, OSObject *) __asm__(
        "__ZN25IOSkywalkPacketBufferPool16deallocatePacketEP15IOSkywalkPacket");
    extern "C" void *skyBytes(const OSObject *) __asm__(
        "__ZNK15IOSkywalkPacket21getDataVirtualAddressEv");
    extern "C" unsigned int skyLength(const OSObject *) __asm__(
        "__ZNK15IOSkywalkPacket13getDataLengthEv");
    extern "C" IOReturn
    skySetLength(OSObject *, unsigned short, unsigned int) __asm__(
        "__ZN15IOSkywalkPacket22setDataOffsetAndLengthEtj");
    extern "C" IOReturn
    skyRequestTxCompletion(OSObject *, void *, unsigned int) __asm__(
        "__ZN26IOSkywalkTxCompletionQueue14requestEnqueueEPvj");
    extern "C" IOReturn
    skyRequestRxCompletion(OSObject *, void *, unsigned int) __asm__(
        "__ZN26IOSkywalkRxCompletionQueue14requestEnqueueEPvj");
    extern "C" IOReturn skyRequestTx(OSObject *, void *, unsigned int) __asm__(
        "__ZN26IOSkywalkTxSubmissionQueue14requestDequeueEPvj");
    extern "C" void
    skyCompleteTx(OSObject *, OSObject **, unsigned int) __asm__(
        "__"
        "ZN26IOSkywalkTxCompletionQueue15completePacketsEPP15IOSkywalkPacketj");

    struct PoolOptions
    {
            uint32_t packets;
            uint32_t buffers;
            uint32_t bufferBytes;
            uint32_t buffersPerPacket;
            uint32_t segmentBytes;
            uint32_t flags;
            uint64_t reserved;
    };

    static_assert(sizeof(PoolOptions) == 32, "native Skywalk pool options");
    constexpr unsigned int kBufferBytes = 2048;
    constexpr unsigned int kMaximumFrame = 1518;
    constexpr unsigned int kNoWait = 1;

    template <typename T> T *prefix(OSObject *object)
    {
        T *result = nullptr;
        static_assert(sizeof(result) == sizeof(object), "native pointer width");
        memcpy(&result, &object, sizeof(result));
        return result;
    }

    void releaseObject(OSObject *&object)
    {
        if (object != nullptr)
        {
            auto *retired = object;
            object = nullptr;
            retired->release();
        }
    }
} // namespace

namespace simpleath
{
    namespace tahoe
    {
        TahoePacketPath::~TahoePacketPath()
        {
            stop();
        }

        IOReturn TahoePacketPath::start(IO80211SkywalkInterface *interface,
                                        SimpleATHTahoeController *controller)
        {
            if (interface == nullptr || controller == nullptr ||
                interface_ != nullptr)
            {
                return kIOReturnBadArgument;
            }
            interface_ = interface;
            controller_ = controller;
            loop_ = controller->getWorkQueue();
            if (loop_ == nullptr)
            {
                stop();
                return kIOReturnNotReady;
            }
            const PoolOptions options {
                kCapacity * 2, kCapacity * 2, kBufferBytes, 1, 4096, 4, 0};
            txPool_ = skyCreatePool("SimpleATH-TX", interface, 1, &options);
            rxPool_ = skyCreatePool("SimpleATH-RX", interface, 1, &options);
            if (txPool_ == nullptr || rxPool_ == nullptr)
            {
                stop();
                return kIOReturnNoMemory;
            }
            queues_[0] = skyCreateTx(txPool_, kCapacity, 0, interface,
                                     &TahoePacketPath::submit, this, 0);
            queues_[1] =
                skyCreateTxCompletion(txPool_, kCapacity, 0, interface,
                                      &TahoePacketPath::complete, this, 0);
            queues_[2] =
                skyCreateRxCompletion(rxPool_, kCapacity, 0, interface,
                                      &TahoePacketPath::receive, this, 0);
            for (auto *queue : queues_)
            {
                if (queue == nullptr ||
                    queue->metaCast("IOEventSource") == nullptr)
                {
                    stop();
                    return kIOReturnNoMemory;
                }
                const IOReturn result =
                    loop_->addEventSource(prefix<IOEventSource>(queue));
                if (result != kIOReturnSuccess)
                {
                    stop();
                    return result;
                }
                ++addedSources_;
            }
            alignas(uint64_t) uint8_t registration[0x130] {};
            if (!skyRegistration(interface_, registration, 1,
                                 sizeof(registration)))
            {
                stop();
                return kIOReturnError;
            }
            // The argument after the queue array is its COUNT, not flags.
            // The native Infra registration preserves WCL and wireless BSD
            // setup; its return value is IOReturn (zero means success).
            const IOReturn result = skyRegister(interface_, registration,
                                                queues_, 3, txPool_, rxPool_);
            if (result != kIOReturnSuccess)
            {
                stop();
                return result;
            }
            registered_ = true;
            return kIOReturnSuccess;
        }

        void TahoePacketPath::stop()
        {
            disable();
            // Accepted TX bytes have already been copied into the radio
            // owner. Return every retained OS packet through its native TX
            // completion path before destroying the interface and pools.
            flushCompletions();
            if (registered_)
            {
                registered_ = false;
                skyDeregister(interface_, 0);
            }
            while (addedSources_ != 0)
            {
                --addedSources_;
                loop_->removeEventSource(
                    prefix<IOEventSource>(queues_[addedSources_]));
            }
            for (auto *&queue : queues_)
            {
                releaseObject(queue);
            }
            releaseObject(rxPool_);
            releaseObject(txPool_);
            controller_ = nullptr;
            interface_ = nullptr;
            loop_ = nullptr;
        }

        IOReturn TahoePacketPath::enable()
        {
            if (!registered_)
            {
                return kIOReturnNotReady;
            }
            if (enabled_)
            {
                return kIOReturnSuccess;
            }
            enabled_ = true;
            for (auto *queue : queues_)
            {
                prefix<IOEventSource>(queue)->enable();
            }
            return kIOReturnSuccess;
        }

        void TahoePacketPath::disable()
        {
            enabled_ = false;
            for (auto *queue : queues_)
            {
                if (queue != nullptr)
                {
                    prefix<IOEventSource>(queue)->disable();
                }
            }
            // A normal association loss disables poll(), not just final
            // stop(). Accepted TX bytes are already copied to the physical
            // owner; complete their OS packets on this same work loop now,
            // or a disabled completion event source would retain them until
            // the interface is destroyed. Repeated disable/stop is harmless.
            flushCompletions();
        }

        void TahoePacketPath::poll()
        {
            if (!enabled_)
            {
                return;
            }
            // Native request methods marshal work to their queue context.
            // Backpressure leaves unconsumed packets in the submission ring.
            if (completedCount_ != 0)
            {
                (void)skyRequestTxCompletion(queues_[1], nullptr, 0);
            }
            (void)skyRequestRxCompletion(queues_[2], nullptr, 0);
            (void)skyRequestTx(queues_[0], nullptr, 0);
        }

        unsigned int TahoePacketPath::submit(OSObject *, OSObject *,
                                             OSObject *const *packets,
                                             unsigned int count, void *context)
        {
            auto *path = static_cast<TahoePacketPath *>(context);
            return path != nullptr ? path->submitPackets(packets, count) : 0;
        }

        unsigned int TahoePacketPath::complete(OSObject *, OSObject *,
                                               OSObject **packets,
                                               unsigned int count,
                                               void *context)
        {
            auto *path = static_cast<TahoePacketPath *>(context);
            return path != nullptr ? path->completePackets(packets, count) : 0;
        }

        unsigned int TahoePacketPath::receive(OSObject *, OSObject *,
                                              OSObject **packets,
                                              unsigned int count, void *context)
        {
            auto *path = static_cast<TahoePacketPath *>(context);
            return path != nullptr ? path->receivePackets(packets, count) : 0;
        }

        unsigned int TahoePacketPath::submitPackets(OSObject *const *packets,
                                                    unsigned int count)
        {
            if (!enabled_ || packets == nullptr)
            {
                return 0;
            }
            unsigned int consumed = 0;
            while (consumed < count && completedCount_ < kCapacity)
            {
                auto *packet = packets[consumed];
                if (packet == nullptr)
                {
                    break;
                }
                const auto length = skyLength(packet);
                const auto *bytes =
                    static_cast<const uint8_t *>(skyBytes(packet));
                const bool malformed =
                    bytes == nullptr || length < 14 || length > kMaximumFrame;
                // The submission callback's return value advances the OS
                // queue, not a physical TX-success counter. A non-null
                // malformed packet must be returned through completion or it
                // would permanently block later valid queue entries. Never
                // submit its bytes to the radio. Provider refusal of a valid
                // packet retains normal queue backpressure instead.
                if (!malformed && controller_->sendEthernet(bytes, length) !=
                                      kIOReturnSuccess)
                {
                    break;
                }
                completed_[(completedHead_ + completedCount_) % kCapacity] =
                    packet;
                ++completedCount_;
                ++consumed;
            }
            return consumed;
        }

        unsigned int TahoePacketPath::completePackets(OSObject **packets,
                                                      unsigned int count)
        {
            if (packets == nullptr)
            {
                return 0;
            }
            unsigned int produced = 0;
            while (produced < count && completedCount_ != 0)
            {
                packets[produced++] = completed_[completedHead_];
                completed_[completedHead_] = nullptr;
                completedHead_ = (completedHead_ + 1) % kCapacity;
                --completedCount_;
            }
            return produced;
        }

        unsigned int TahoePacketPath::receivePackets(OSObject **packets,
                                                     unsigned int count)
        {
            if (!enabled_ || packets == nullptr)
            {
                return 0;
            }
            unsigned int produced = 0;
            while (produced < count && produced < kCapacity)
            {
                OSObject *packet = nullptr;
                if (skyAllocate(rxPool_, &packet, kNoWait) !=
                        kIOReturnSuccess ||
                    packet == nullptr)
                {
                    break;
                }
                if (skyPrepare(packet, nullptr, 2, 0) != kIOReturnSuccess)
                {
                    (void)skyCompletePacket(packet, nullptr, 2, 0);
                    skyDeallocate(rxPool_, packet);
                    break;
                }
                auto *bytes = static_cast<uint8_t *>(skyBytes(packet));
                size_t length = 0;
                const IOReturn result = bytes != nullptr
                                            ? controller_->receiveEthernet(
                                                  bytes, kBufferBytes, length)
                                            : kIOReturnNoMemory;
                if (result != kIOReturnSuccess || length < 14 ||
                    length > kMaximumFrame ||
                    skySetLength(packet, 0,
                                 static_cast<unsigned int>(length)) !=
                        kIOReturnSuccess)
                {
                    (void)skyCompletePacket(packet, nullptr, 2, 0);
                    skyDeallocate(rxPool_, packet);
                    break;
                }
                packets[produced++] = packet;
            }
            return produced;
        }

        void TahoePacketPath::flushCompletions()
        {
            while (completedCount_ != 0 && queues_[1] != nullptr)
            {
                OSObject *packet = nullptr;
                if (completePackets(&packet, 1) != 1)
                {
                    break;
                }
                // Native completion performs packet completeWithQueue and
                // returns it to the pool. Do not also release/deallocate it.
                skyCompleteTx(queues_[1], &packet, 1);
            }
        }

        OSObject *TahoePacketPath::txSubmission() const
        {
            return queues_[0];
        }

        OSObject *TahoePacketPath::txCompletion() const
        {
            return queues_[1];
        }

        OSObject *TahoePacketPath::rxCompletion() const
        {
            return queues_[2];
        }

        OSObject *TahoePacketPath::txPool() const
        {
            return txPool_;
        }

        OSObject *TahoePacketPath::rxPool() const
        {
            return rxPool_;
        }

        bool TahoePacketPath::registered() const
        {
            return registered_;
        }
    } // namespace tahoe
} // namespace simpleath
