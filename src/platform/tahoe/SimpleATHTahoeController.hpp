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
//   - Native driver contracts and implementation for simple athtahoe
//     controller.
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
//   - Native driver contracts and implementation for simple athtahoe
//     controller.
// - Description:
//   - Implements or verifies the SimpleATHTahoeController source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: simple athtahoe controller.

// Exact-25G332 IO80211Controller entrypoint for a physical AR9565 owner.
#ifndef SIMPLEATH_TAHOE_CONTROLLER_HPP
#define SIMPLEATH_TAHOE_CONTROLLER_HPP

#include "TahoeCapture.hpp"
#include "TahoeControllerABI.hpp"
#include "TahoeWirelessTransport.hpp"

class SimpleATHInfraProtocol;

// This class is a genuine modern IO80211Controller subclass, not an Ethernet
// interface impersonation. Its concrete InfraProtocol owns native Skywalk
// registration, packet queues and serialized WCL request/event dispatch.
class SimpleATHTahoeController final : public IO80211Controller
{
    private:
        static constexpr const OSMetaClass *superClass =
            &IO80211Controller::gMetaClass;

    public:
        static const OSMetaClass *const metaClass;

        static class MetaClass : public OSMetaClass
        {
            public:
                MetaClass() noexcept;
                OSObject *alloc() const APPLE_KEXT_OVERRIDE;
        } gMetaClass;
        friend class SimpleATHTahoeController::MetaClass;
        const OSMetaClass *getMetaClass() const APPLE_KEXT_OVERRIDE;
        // Tahoe OSDefineDefaultStructors emits these allocation methods.
        // Keep the SDK-defined allocation/free implementation paired
        // with its declarations; this does not alter the vtable.
        void *operator new(size_t size);
        void operator delete(void *memory, size_t size);

        SimpleATHTahoeController();
        SimpleATHTahoeController(const SimpleATHTahoeController &) = delete;
        SimpleATHTahoeController &
        operator=(const SimpleATHTahoeController &) = delete;
        SimpleATHTahoeController(SimpleATHTahoeController &&) = delete;
        SimpleATHTahoeController &
        operator=(SimpleATHTahoeController &&) = delete;
        ~SimpleATHTahoeController() APPLE_KEXT_OVERRIDE;

    protected:
        explicit SimpleATHTahoeController(const OSMetaClass *meta);

    public:
        bool init(OSDictionary *properties) override;
        bool start(IOService *provider) override;
        void stop(IOService *provider) override;

    protected:
        void free() override;

    public:
        bool createWorkQueue() override;
        IO80211WorkQueue *getWorkQueue() const override;
        bool getLogPipes(CCPipe **logs, CCPipe **data,
                         CCPipe **snapshots) override;
        bool isCommandProhibited(int command) override;
        IOReturn getHardwareAddress(IOEthernetAddress *out) override;
        IOReturn getDriverVersion(IO80211SkywalkInterface * /*unused*/,
                                  void * /*buffer*/) override;
        IOReturn getHardwareVersion(IO80211SkywalkInterface * /*unused*/,
                                    void * /*buffer*/) override;
        IOReturn getCardCapabilities(IO80211SkywalkInterface * /*unused*/,
                                     void * /*buffer*/) override;
        IOReturn getPOWER(IO80211SkywalkInterface * /*unused*/,
                          void * /*buffer*/) override;
        IOReturn setPOWER(IO80211SkywalkInterface * /*unused*/,
                          void * /*buffer*/) override;
        IOReturn getCountryCode(IO80211SkywalkInterface * /*unused*/,
                                void * /*buffer*/) override;
        IOReturn setCountryCode(IO80211SkywalkInterface * /*unused*/,
                                void * /*buffer*/) override;
        IOReturn setGetDebugInfo(IO80211SkywalkInterface * /*unused*/,
                                 void * /*buffer*/) override;
        int32_t handleCardSpecific(IO80211SkywalkInterface * /*unused*/,
                                   unsigned long /*unused*/, void * /*unused*/,
                                   bool /*unused*/) override;
        CCLogStream *getLogger() const override;
        CommonFaultReporter *getFaultReporterFromDriver() override;

        // Concrete InfraProtocol and packet callbacks copy all borrowed data
        // synchronously through the epoch-scoped physical radio owner.
        IOReturn radioPower(bool on);
        IOReturn radioMac(const uint8_t address[6]);
        IOReturn radioSnapshot(simpleath::tahoe::WirelessSnapshot &out);
        IOReturn scanStart(uint64_t &generation);
        IOReturn scanCancel(uint64_t generation);
        IOReturn scanNext(uint64_t generation,
                          simpleath::ieee80211::NativeBssSnapshot &out);
        IOReturn
        stationJoin(const simpleath::tahoe::NativeConnectRequest &request);
        IOReturn stationLeave(uint16_t reason);
        IOReturn setCcmpKey(const simpleath::tahoe::NativeCcmpKey &key);
        IOReturn setControlledPort(bool enabled);
        IOReturn sendEthernet(const uint8_t *packet, size_t length);
        IOReturn nextRadioEvent(simpleath::tahoe::WirelessEvent &event,
                                uint64_t &epoch, uint64_t &generation);
        IOReturn receiveEthernet(uint8_t *packet, size_t capacity,
                                 size_t &length);

    private:
        void releaseInfrastructure();
        SimpleATHInfraProtocol *infrastructure_ {nullptr};
        bool infrastructureAttached_ {false};
        bool nativeAttached_ {false};
        bool infrastructurePublished_ {false};
        simpleath::tahoe::TahoeWirelessTransport transport_;
        simpleath::tahoe::TahoeCapture capture_;
        IO80211WorkQueue *workQueue_ {nullptr};
        bool started_ {false};
};
#endif
