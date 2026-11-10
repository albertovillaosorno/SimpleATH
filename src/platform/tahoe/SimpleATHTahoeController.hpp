// SPDX-License-Identifier: AGPL-3.0-only
// Exact-25G332 IO80211Controller entrypoint for a physical AR9565 owner.
#ifndef SIMPLEATH_TAHOE_CONTROLLER_HPP
#define SIMPLEATH_TAHOE_CONTROLLER_HPP

#include "TahoeCapture.hpp"
#include "TahoeControllerABI.hpp"
#include "TahoeWirelessTransport.hpp"

// This class is a genuine modern IO80211Controller subclass, not an Ethernet
// interface impersonation. The Tahoe IO80211InfraProtocol, Skywalk packet pool
// and exact Apple80211/WCL dispatch are separate mandatory integration steps.
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

        // These entrypoints are used only by the eventual verified modern
        // InfraProtocol and WCL handlers; callers own their request buffers.
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
                                uint64_t &epoch);
        IOReturn receiveEthernet(uint8_t *packet, size_t capacity,
                                 size_t &length);

    private:
        simpleath::tahoe::TahoeWirelessTransport transport_;
        simpleath::tahoe::TahoeCapture capture_;
        IO80211WorkQueue *workQueue_ {nullptr};
        bool started_ {false};
};
#endif
