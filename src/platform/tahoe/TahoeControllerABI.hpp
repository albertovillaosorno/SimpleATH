// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 SimpleATH contributors.
// Independently declared ABI from the Intel 25G332 KDK symbol/vtable image.
#ifndef SIMPLEATH_TAHOE_CONTROLLER_ABI_HPP
#define SIMPLEATH_TAHOE_CONTROLLER_ABI_HPP
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IOEthernetController.h>
#include <stddef.h>
#include <stdint.h>

namespace simpleath
{
    namespace tahoe
    {
        constexpr size_t kWorkQueueAbiBytes = 0x50U;
        constexpr size_t kEthernetControllerAbiBytes = 0x118U;
        constexpr size_t kWirelessControllerAbiBytes = 0x128U;
    } // namespace tahoe
} // namespace simpleath
class IO80211SkywalkInterface;
class CCLogStream;
class CCPipe;
class CommonFaultReporter;

class IO80211WorkQueue : public IOWorkLoop
{
        // Expand the IOKit metaclass declaration to express ownership
        // explicitly. These declarations preserve the imported 25G332 object
        // and vtable ABI.
    private:
        static const OSMetaClass *const superClass;

    public:
        static const OSMetaClass *const metaClass;

        static class MetaClass : public OSMetaClass
        {
            public:
                MetaClass();
                OSObject *alloc() const APPLE_KEXT_OVERRIDE;
        } gMetaClass;
        friend class IO80211WorkQueue::MetaClass;
        const OSMetaClass *getMetaClass() const APPLE_KEXT_OVERRIDE;
        IO80211WorkQueue(const IO80211WorkQueue &) = delete;
        IO80211WorkQueue &operator=(const IO80211WorkQueue &) = delete;
        IO80211WorkQueue(IO80211WorkQueue &&) = delete;
        IO80211WorkQueue &operator=(IO80211WorkQueue &&) = delete;
        ~IO80211WorkQueue() APPLE_KEXT_OVERRIDE;

    protected:
        explicit IO80211WorkQueue(const OSMetaClass *);

    private:
        IO80211WorkQueue();
        uint8_t nativeStorage_[simpleath::tahoe::kWorkQueueAbiBytes -
                               sizeof(IOWorkLoop)];
};

static_assert(sizeof(IO80211WorkQueue) == simpleath::tahoe::kWorkQueueAbiBytes,
              "25G332 IO80211 work queue size");

// Pure virtual Apple80211 dispatch uses the verified *slot order*, not
// exported name references to this subclass. C++-style source names for the
// locally implemented overrides do not re-order or resize that ABI.
// Native-owned methods with opaque private parameter types are imported at
// their exact slots below. They have no replacement implementation and must
// never be called through these opaque source declarations. Typed methods and
// required driver overrides retain the actual x86_64 calling convention.
class IO80211Controller : public IOEthernetController
{
    private:
        static const OSMetaClass *const superClass;

    public:
        static const OSMetaClass *const metaClass;

        static class MetaClass : public OSMetaClass
        {
            public:
                MetaClass();
                OSObject *alloc() const APPLE_KEXT_OVERRIDE;
        } gMetaClass;
        friend class IO80211Controller::MetaClass;
        const OSMetaClass *getMetaClass() const APPLE_KEXT_OVERRIDE;
        IO80211Controller(const IO80211Controller &) = delete;
        IO80211Controller &operator=(const IO80211Controller &) = delete;
        IO80211Controller(IO80211Controller &&) = delete;
        IO80211Controller &operator=(IO80211Controller &&) = delete;
        ~IO80211Controller() APPLE_KEXT_OVERRIDE;

    protected:
        explicit IO80211Controller(const OSMetaClass *);
        void free() override;

    private:
        IO80211Controller();

    public:
        bool init(OSDictionary * /*properties*/) override;
        IOReturn configureReport(IOReportChannelList * /*channels*/,
                                 unsigned int /*action*/, void * /*result*/,
                                 void * /*destination*/) override;
        IOReturn updateReport(IOReportChannelList * /*channels*/,
                              unsigned int /*action*/, void * /*result*/,
                              void * /*destination*/) override;
        bool start(IOService * /*provider*/) override;
        void stop(IOService * /*provider*/) override;
        IOWorkLoop *getWorkLoop() const override;
        const char *stringFromReturn(int /*rtn*/) override;
        int errnoFromReturn(int /*rtn*/) override;
        UInt32 getFeatures() const override;
        const OSString *newVendorString() const override;
        const OSString *newModelString() const override;

    protected:
        bool createWorkLoop() override;

    public:
        IOReturn getHardwareAddress(IOEthernetAddress * /*addrP*/) override;
        IOReturn setMulticastMode(bool /*active*/) override;
        IOReturn setPromiscuousMode(bool /*active*/) override;
        // These two occupied IONetworkController reserve slots in the older
        // SDK.
    private:
        void _RESERVEDIONetworkController6() __asm__(
            "__ZN19IONetworkController20allocatePacketNoWaitEj") override;
        void _RESERVEDIONetworkController7() __asm__(
            "__ZN19IONetworkController18setHardwareAssistsEjj") override;

    public:
        virtual bool isCommandProhibited(int) = 0; // slot 0x0c50

        virtual bool createWorkQueue(); // slot 0x0c58
    private:
        virtual void
        nativeSlot0C60() __asm__("__ZN17IO80211Controller14debugStateInitEv");

    public:
        virtual IO80211WorkQueue *getWorkQueue() const; // slot 0x0c68

        virtual void requestPacketTx(void *, unsigned int); // slot 0x0c70

        virtual IOCommandGate *getIO80211CommandGate() const; // slot 0x0c78

        virtual IO80211SkywalkInterface *
        getPrimarySkywalkInterface(); // slot 0x0c80

        virtual int bpfOutputPacket(OSObject *, unsigned int,
                                    mbuf_t); // slot 0x0c88

        virtual int32_t monitorModeSetEnabled(bool,
                                              unsigned int); // slot 0x0c90

        virtual int32_t handleCardSpecific(IO80211SkywalkInterface *,
                                           unsigned long, void *,
                                           bool) = 0; // slot 0x0c98

        virtual uint32_t hardwareOutputQueueDepth(); // slot 0x0ca0
    private:
        virtual void
        nativeSlot0CA8() __asm__("__"
                                 "ZN17IO80211Controller27performCountryCodeOper"
                                 "ationE20IO80211CountryCodeOp");

    public:
        virtual void dataLinkLayerAttachComplete(); // slot 0x0cb0
    private:
        virtual void nativeSlot0CB8() __asm__(
            "__ZN17IO80211Controller13enableFeatureE18IO80211FeatureCodePv");

    public:
        virtual IOReturn getDriverVersion(IO80211SkywalkInterface *,
                                          void *) = 0; // slot 0x0cc0

        virtual IOReturn getHardwareVersion(IO80211SkywalkInterface *,
                                            void *) = 0; // slot 0x0cc8

        virtual IOReturn getCardCapabilities(IO80211SkywalkInterface *,
                                             void *) = 0; // slot 0x0cd0

        virtual IOReturn getPOWER(IO80211SkywalkInterface *,
                                  void *) = 0; // slot 0x0cd8

        virtual IOReturn setPOWER(IO80211SkywalkInterface *,
                                  void *) = 0; // slot 0x0ce0

        virtual IOReturn getCountryCode(IO80211SkywalkInterface *,
                                        void *) = 0; // slot 0x0ce8

        virtual IOReturn setCountryCode(IO80211SkywalkInterface *,
                                        void *) = 0; // slot 0x0cf0

        virtual IOReturn setGetDebugInfo(IO80211SkywalkInterface *,
                                         void *) = 0; // slot 0x0cf8
    private:
        virtual void nativeSlot0D00() __asm__(
            "__ZN17IO80211Controller18getPLATFORM_"
            "CONFIGEP23IO80211SkywalkInterfaceP26apple80211_platform_config");

        virtual void
        nativeSlot0D08() __asm__("__"
                                 "ZN17IO80211Controller22enableVirtualInterface"
                                 "EP23IO80211VirtualInterface");

        virtual void
        nativeSlot0D10() __asm__("__"
                                 "ZN17IO80211Controller23disableVirtualInterfac"
                                 "eEP23IO80211VirtualInterface");

    public:
        virtual bool requiresExplicitMBufRelease(); // slot 0x0d18

        virtual bool flowIdSupported(); // slot 0x0d20
    private:
        virtual void nativeSlot0D28() __asm__(
            "__ZN17IO80211Controller16requestFlowQueueEPK14FlowIdMetadata");

        virtual void nativeSlot0D30() __asm__(
            "__ZN17IO80211Controller16releaseFlowQueueEP16IO80211FlowQueue");

    public:
        virtual bool getLogPipes(CCPipe **, CCPipe **,
                                 CCPipe **); // slot 0x0d38

        virtual CCLogStream *getLogger() const = 0; // slot 0x0d40
    private:
        virtual void nativeSlot0D48() __asm__(
            "__ZN17IO80211Controller28enableFeatureForLoggingFlagsEy");

        virtual void nativeSlot0D50() __asm__(
            "__ZN17IO80211Controller26requestQueueSizeAndTimeoutEPtS0_");

        virtual void nativeSlot0D58() __asm__(
            "__ZN17IO80211Controller24enablePacketTimestampingEv");

        virtual void nativeSlot0D60() __asm__(
            "__ZN17IO80211Controller25disablePacketTimestampingEv");

        virtual void nativeSlot0D68() __asm__(
            "__ZN17IO80211Controller18getPacketTSCounterEv");

        virtual void
        nativeSlot0D70() __asm__("__ZN17IO80211Controller16getDriverTextLogEv");

        virtual void nativeSlot0D78() __asm__(
            "__ZN17IO80211Controller21selfDiagnosticsReportEiPKcj");

    public:
        virtual CommonFaultReporter *
        getFaultReporterFromDriver() = 0; // slot 0x0d80
    private:
        virtual void nativeSlot0D88() __asm__(
            "__ZN17IO80211Controller25allocIO80211RecursiveLockEv");

        virtual void nativeSlot0D90() __asm__(
            "__ZN17IO80211Controller17getDataQueueDepthEP8OSObject");

        virtual void nativeSlot0D98() __asm__(
            "__ZN17IO80211Controller23wasDynSARInFailSafeModeEv");

        virtual void nativeSlot0DA0() __asm__(
            "__ZN17IO80211Controller26updateAdvisoryScoresIfNeedEv");

        virtual void
        nativeSlot0DA8() __asm__("__"
                                 "ZN17IO80211Controller18getAVCAdvisoryInfoEP27"
                                 "IO80211InterfaceAVCAdvisory");

        virtual void nativeSlot0DB0() __asm__(
            "__ZN17IO80211Controller26getActionFramePoolCapacityEv");

        virtual void
        nativeSlot0DB8() __asm__("__ZN17IO80211Controller13getPostOfficeEv");

        virtual void
        nativeSlot0DC0() __asm__("__ZN17IO80211Controller16CreatePostOfficeEv");

    public:
        virtual bool attachInterface(OSObject *, IOService *); // slot 0x0dc8

        virtual void detachInterface(OSObject *, bool); // slot 0x0dd0
    private:
        virtual void nativeSlot0DD8() __asm__(
            "__ZN17IO80211Controller22createVirtualInterfaceEP10ether_addrj");

        virtual void
        nativeSlot0DE0() __asm__("__"
                                 "ZN17IO80211Controller22attachVirtualInterface"
                                 "EPP23IO80211VirtualInterfaceP10ether_addrjb");

        virtual void
        nativeSlot0DE8() __asm__("__"
                                 "ZN17IO80211Controller22detachVirtualInterface"
                                 "EP23IO80211VirtualInterfaceb");

        virtual void nativeSlot0DF0() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller0Ev");

        virtual void nativeSlot0DF8() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller1Ev");

        virtual void nativeSlot0E00() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller2Ev");

        virtual void nativeSlot0E08() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller3Ev");

        virtual void nativeSlot0E10() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller4Ev");

        virtual void nativeSlot0E18() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller5Ev");

        virtual void nativeSlot0E20() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller6Ev");

        virtual void nativeSlot0E28() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller7Ev");

        virtual void nativeSlot0E30() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller8Ev");

        virtual void nativeSlot0E38() __asm__(
            "__ZN17IO80211Controller27_RESERVEDIO80211Controller9Ev");

        virtual void nativeSlot0E40() __asm__(
            "__ZN17IO80211Controller28_RESERVEDIO80211Controller10Ev");

        virtual void nativeSlot0E48() __asm__(
            "__ZN17IO80211Controller28_RESERVEDIO80211Controller11Ev");

        virtual void nativeSlot0E50() __asm__(
            "__ZN17IO80211Controller28_RESERVEDIO80211Controller12Ev");

        virtual void nativeSlot0E58() __asm__(
            "__ZN17IO80211Controller28_RESERVEDIO80211Controller13Ev");

        virtual void nativeSlot0E60() __asm__(
            "__ZN17IO80211Controller28_RESERVEDIO80211Controller14Ev");

        virtual void nativeSlot0E68() __asm__(
            "__ZN17IO80211Controller28_RESERVEDIO80211Controller15Ev");

    public:
        virtual IOReturn setMulticastList(const struct EtherAddr *,
                                          unsigned int); // slot 0x0e70
    private:
        uint8_t nativeStorage_[simpleath::tahoe::kWirelessControllerAbiBytes -
                               sizeof(IOEthernetController)];
};

static_assert(sizeof(IOEthernetController) ==
                  simpleath::tahoe::kEthernetControllerAbiBytes,
              "25G332 Ethernet controller size");
static_assert(sizeof(IO80211Controller) ==
                  simpleath::tahoe::kWirelessControllerAbiBytes,
              "25G332 wireless controller size");
#endif
