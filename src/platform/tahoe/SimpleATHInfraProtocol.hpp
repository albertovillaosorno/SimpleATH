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
//   - Native driver contracts and implementation for simple athinfra protocol.
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
//   - Native driver contracts and implementation for simple athinfra protocol.
// - Description:
//   - Implements or verifies the SimpleATHInfraProtocol source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: simple athinfra protocol.

#ifndef SIMPLEATH_TAHOE_INFRA_PROTOCOL_HPP
#define SIMPLEATH_TAHOE_INFRA_PROTOCOL_HPP
#include "NativeWirelessOwner.hpp"
#include "TahoeInterfaceABI.hpp"
#include "TahoeJoinCodec.hpp"
#include "TahoeJoinEvents.hpp"
#include "TahoePacketPath.hpp"
#include "TahoeScanCodec.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
#include <stddef.h>
class SimpleATHTahoeController;

class SimpleATHInfraProtocol final : public IO80211InfraProtocol
{
    private:
        static constexpr const OSMetaClass *superClass =
            &IO80211InfraProtocol::gMetaClass;

    public:
        static const OSMetaClass *const metaClass;

        static class MetaClass : public OSMetaClass
        {
            public:
                MetaClass() noexcept;
                OSObject *alloc() const APPLE_KEXT_OVERRIDE;
        } gMetaClass;
        friend class SimpleATHInfraProtocol::MetaClass;
        const OSMetaClass *getMetaClass() const APPLE_KEXT_OVERRIDE;
        // Tahoe OSDefineDefaultStructors emits these allocation methods.
        // Keep the SDK-defined allocation/free implementation paired
        // with its declarations; this does not alter the vtable.
        void *operator new(size_t size);
        void operator delete(void *memory, size_t size);

        SimpleATHInfraProtocol();
        SimpleATHInfraProtocol(const SimpleATHInfraProtocol &) = delete;
        SimpleATHInfraProtocol &
        operator=(const SimpleATHInfraProtocol &) = delete;
        SimpleATHInfraProtocol(SimpleATHInfraProtocol &&) = delete;
        SimpleATHInfraProtocol &operator=(SimpleATHInfraProtocol &&) = delete;
        ~SimpleATHInfraProtocol() APPLE_KEXT_OVERRIDE;

    protected:
        explicit SimpleATHInfraProtocol(const OSMetaClass *meta);

    public:
        bool initialize(SimpleATHTahoeController *controller);
        bool start(IOService *provider) override;
        void stop(IOService *provider) override;
        IOWorkLoop *getWorkLoop() const override;
        IOReturn enable(unsigned int options) override;
        IOReturn disable(unsigned int options) override;
        IOReturn enableDatapath() override;
        IOReturn disableDatapath() override;
        bool isChipInterfaceReady() override;
        bool isCommandProhibited(int command) override;
        IOReturn getHardwareAddress(ether_addr *out) override;
        IOReturn setHardwareAddress(ether_addr *address) override;
        IOReturn setMacAddress(void *addresses) override;
        uint64_t getSelfMacAddr() override;
        OSObject *getRxCompQueue() override;
        OSObject *getTxCompQueue() override;
        OSObject *getTxSubQueue(unsigned int category) override;
        OSObject *getTxPacketPool() override;
        OSObject *getRxPacketPool() override;
        unsigned int getNumTxQueues() override;
        IOSkywalkPacketBufferPool *getPacketPool(OSString *name) override;
        CCLogStream *getLogger() const override;
        uint32_t getHardwareAssists() override;
        uint32_t getMaxTransferUnit() override;
        int getAssocState() override;
        IO80211LinkState linkState() override;
#define SIMPLEATH_INFRA_OPERATION(name, slot)                                  \
    IOReturn name(void *request) override;
#include "TahoeInfraOperations.inc"
#undef SIMPLEATH_INFRA_OPERATION
    protected:
        void free() override;

    private:
        static IOReturn requestAction(OSObject *, void *, void *, void *,
                                      void *);
        static IOReturn stopAction(OSObject *, void *, void *, void *, void *);
        static void tick(OSObject *, IOTimerEventSource *);
        IOReturn request(unsigned int operation, void *data);
        IOReturn requestGated(unsigned int operation, void *data);
        IOReturn beginJoin(void *data);
        IOReturn leaveJoin(bool abort);
        void pollJoin(const simpleath::tahoe::WirelessSnapshot &state,
                      bool live);
        void emitJoin(unsigned int message, IOReturn status, uint16_t reason,
                      bool up);
        void retireJoin(IOReturn status, uint16_t reason);
        IOReturn beginScan(void *data);
        void finishScan(bool canceled);
        void poll();
        void shutdown();
        void emit(unsigned int event, void *bytes, size_t length);
        SimpleATHTahoeController *controller_ {nullptr};
        IOCommandGate *gate_ {nullptr};
        IOTimerEventSource *timer_ {nullptr};
        simpleath::tahoe::TahoePacketPath packets_;
        simpleath::tahoe::ScanFilter scan_ {};
        simpleath::tahoe::JoinSession join_;
        uint64_t joinSerial_ {0};
        uint64_t joinDeadline_ {0};
        uint64_t scanGeneration_ {0};
        uint64_t scanEpoch_ {0};
        uint64_t lastEpoch_ {0};
        bool parentStarted_ {false};
        bool gateAdded_ {false};
        bool timerAdded_ {false};
        bool stopping_ {false};
        bool available_ {false};
        bool linked_ {false};
        bool dataRequested_ {false};
        uint64_t dataRequestEpoch_ {0};
};
#endif
