#ifndef SIMPLEATH_TAHOE_INFRA_PROTOCOL_HPP
#define SIMPLEATH_TAHOE_INFRA_PROTOCOL_HPP
#include "TahoeInterfaceABI.hpp"
#include "TahoePacketPath.hpp"
#include "TahoeScanCodec.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOTimerEventSource.h>
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
};
#endif
