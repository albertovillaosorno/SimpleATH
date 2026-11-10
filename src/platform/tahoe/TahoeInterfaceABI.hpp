// Independently declared from Intel Tahoe 25G332 native symbols/vtables.
#ifndef SIMPLEATH_TAHOE_INTERFACE_ABI_HPP
#define SIMPLEATH_TAHOE_INTERFACE_ABI_HPP
#include "TahoeControllerABI.hpp"
#include <IOKit/IOService.h>
#include <net/ethernet.h>
#include <net/kpi_interface.h>
class IOSkywalkPacketBufferPool;
class IO80211NetworkPacket;
struct apple80211_scan_data;
enum IO80211LinkState : uint32_t;

// IOService is the binary-compatible single-inheritance prefix of the native
// IOSkywalk hierarchy. Its native constructors/metaclasses retain the actual
// Apple ancestry. Each remaining native slot is imported explicitly; no SDK
// Skywalk declaration with a different layout is allowed in this translation
// unit.
class IO80211SkywalkInterface : public IOService
{
    OSDeclareAbstractStructors(IO80211SkywalkInterface) public
        : bool init() override;
        void free() override;
        IOReturn configureReport(IOReportChannelList *, unsigned int, void *,
                                 void *) override;
        IOReturn updateReport(IOReportChannelList *, unsigned int, void *,
                              void *) override;
        bool start(IOService *) override;
        void stop(IOService *) override;
        IOReturn newUserClient(task_t, void *, UInt32, OSDictionary *,
                               IOUserClient **) override;
        const char *stringFromReturn(int) override;
        int errnoFromReturn(int) override;
        IOReturn setPowerState(unsigned long, IOService *) override;
        unsigned long maxCapabilityForDomainState(IOPMPowerFlags) override;
        unsigned long initialPowerStateForDomainState(IOPMPowerFlags) override;
        void setInterfaceRole(unsigned int);
        void setInterfaceId(unsigned int);

    public:
        virtual IOReturn enable(unsigned int) __asm__(
            "__ZN23IO80211SkywalkInterface6enableEj"); // 0x0850
    public:
        virtual IOReturn disable(unsigned int) __asm__(
            "__ZN23IO80211SkywalkInterface7disableEj"); // 0x0858
    private:
        virtual void nativeSlot0860() __asm__(
            "__"
            "ZN18IOSkywalkInterface21clientConnectWithTaskEP4taskP9IOServicej");

    private:
        virtual void nativeSlot0868() __asm__(
            "__ZN18IOSkywalkInterface16clientDisconnectEP9IOServicej");

    private:
        virtual void
        nativeSlot0870() __asm__("__ZN18IOSkywalkInterface13isTerminatingEv");

    private:
        virtual void nativeSlot0878() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface0Ev");

    private:
        virtual void nativeSlot0880() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface1Ev");

    private:
        virtual void nativeSlot0888() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface2Ev");

    private:
        virtual void nativeSlot0890() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface3Ev");

    private:
        virtual void nativeSlot0898() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface4Ev");

    private:
        virtual void nativeSlot08A0() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface5Ev");

    private:
        virtual void nativeSlot08A8() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface6Ev");

    private:
        virtual void nativeSlot08B0() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface7Ev");

    private:
        virtual void nativeSlot08B8() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface8Ev");

    private:
        virtual void nativeSlot08C0() __asm__(
            "__ZN18IOSkywalkInterface28_RESERVEDIOSkywalkInterface9Ev");

    private:
        virtual void nativeSlot08C8() __asm__(
            "__ZN18IOSkywalkInterface29_RESERVEDIOSkywalkInterface10Ev");

    private:
        virtual void
        nativeSlot08D0() __asm__("__"
                                 "ZN25IOSkywalkNetworkInterface39registerNetwor"
                                 "kInterfaceWithLogicalLinkEPKNS_"
                                 "16RegistrationInfoEP20IOSkywalkLogicalLinkP25"
                                 "IOSkywalkPacketBufferPoolS6_j");

    private:
        virtual void nativeSlot08D8() __asm__(
            "__ZN25IOSkywalkNetworkInterface21deregisterLogicalLinkEv");

    private:
        virtual void nativeSlot08E0() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface26initBSDInterfaceParametersEP18ifnet_"
            "init_eparamsPP11sockaddr_dl");

    private:
        virtual void nativeSlot08E8() __asm__(
            "__ZN23IO80211SkywalkInterface19prepareBSDInterfaceEP7__ifnetj");

    private:
        virtual void nativeSlot08F0() __asm__(
            "__ZN25IOSkywalkNetworkInterface20finalizeBSDInterfaceEP7__ifnetj");

    public:
        virtual ifnet_t getBSDInterface() const __asm__(
            "__ZNK25IOSkywalkNetworkInterface15getBSDInterfaceEv"); // 0x08f8
    private:
        virtual void nativeSlot0900() __asm__(
            "__ZN25IOSkywalkNetworkInterface10setBSDNameEPKc");

    private:
        virtual void nativeSlot0908() __asm__(
            "__ZNK25IOSkywalkNetworkInterface10getBSDNameEv");

    private:
        virtual void nativeSlot0910() __asm__(
            "__ZN23IO80211SkywalkInterface17processBSDCommandEP7__ifnetjPv");

    private:
        virtual void nativeSlot0918() __asm__(
            "__ZN25IOSkywalkNetworkInterface23processInterfaceCommandEP5ifdrv");

    private:
        virtual void nativeSlot0920() __asm__(
            "__ZN25IOSkywalkNetworkInterface23interfaceAdvisoryEnableEb");

    private:
        virtual void nativeSlot0928() __asm__(
            "__ZN25IOSkywalkNetworkInterface17setRxFlowSteeringEjP31ifnet_"
            "traffic_descriptor_commonj");

    public:
        virtual int32_t setInterfaceEnable(bool) __asm__(
            "__ZN23IO80211SkywalkInterface18setInterfaceEnableEb"); // 0x0930
    public:
        virtual void setRunningState(bool) __asm__(
            "__ZN23IO80211SkywalkInterface15setRunningStateEb"); // 0x0938
    private:
        virtual void nativeSlot0940() __asm__(
            "__ZN23IO80211SkywalkInterface17handleChosenMediaEj");

    private:
        virtual void nativeSlot0948() __asm__(
            "__ZN23IO80211SkywalkInterface22getSupportedMediaArrayEPjS0_");

    private:
        virtual void nativeSlot0950() __asm__(
            "__ZN26IOSkywalkEthernetInterface16getPacketTapInfoEPjS0_");

    private:
        virtual void nativeSlot0958() __asm__(
            "__ZNK25IOSkywalkNetworkInterface22getUnsentDataByteCountEPjS0_j");

    private:
        virtual void nativeSlot0960() __asm__(
            "__ZN25IOSkywalkNetworkInterface21getSupportedWakeFlagsEPj");

    private:
        virtual void nativeSlot0968() __asm__(
            "__ZN26IOSkywalkEthernetInterface17enableNetworkWakeEj");

    private:
        virtual void
        nativeSlot0970() __asm__("__"
                                 "ZNK25IOSkywalkNetworkInterface25calculateRing"
                                 "SizeForQueueEPK20IOSkywalkPacketQueuePj");

    public:
        virtual uint32_t getMaxTransferUnit() __asm__(
            "__ZN26IOSkywalkEthernetInterface18getMaxTransferUnitEv"); // 0x0978
    private:
        virtual void nativeSlot0980() __asm__(
            "__ZN25IOSkywalkNetworkInterface18setMaxTransferUnitEj");

    private:
        virtual void nativeSlot0988() __asm__(
            "__ZN26IOSkywalkEthernetInterface16getMinPacketSizeEv");

    public:
        virtual uint32_t getHardwareAssists() __asm__(
            "__ZN25IOSkywalkNetworkInterface18getHardwareAssistsEv"); // 0x0990
    private:
        virtual void nativeSlot0998() __asm__(
            "__ZN25IOSkywalkNetworkInterface18setHardwareAssistsEjj");

    private:
        virtual void nativeSlot09A0() __asm__(
            "__ZN26IOSkywalkEthernetInterface18getInterfaceFamilyEv");

    private:
        virtual void nativeSlot09A8() __asm__(
            "__ZN26IOSkywalkEthernetInterface21getInterfaceSubFamilyEv");

    private:
        virtual void nativeSlot09B0() __asm__(
            "__ZN26IOSkywalkEthernetInterface15getInitialMediaEv");

    public:
        virtual uint32_t getFeatureFlags() __asm__(
            "__ZN23IO80211SkywalkInterface15getFeatureFlagsEv"); // 0x09b8
    private:
        virtual void nativeSlot09C0() __asm__(
            "__ZN25IOSkywalkNetworkInterface15getTxDataOffsetEv");

    private:
        virtual void nativeSlot09C8() __asm__(
            "__ZN25IOSkywalkNetworkInterface21captureInterfaceStateEj");

    private:
        virtual void nativeSlot09D0() __asm__(
            "__ZN25IOSkywalkNetworkInterface21restoreInterfaceStateEj");

    private:
        virtual void
        nativeSlot09D8() __asm__("__ZN25IOSkywalkNetworkInterface6setMTUEj");

    private:
        virtual void
        nativeSlot09E0() __asm__("__ZN25IOSkywalkNetworkInterface6bpfTapEjj");

    public:
        virtual const char *getBSDNamePrefix() __asm__(
            "__ZN26IOSkywalkEthernetInterface16getBSDNamePrefixEv"); // 0x09e8
    private:
        virtual void nativeSlot09F0() __asm__(
            "__ZN25IOSkywalkNetworkInterface16getBSDUnitNumberEv");

    public:
        virtual const char *classNameOverride() __asm__(
            "__ZN23IO80211SkywalkInterface17classNameOverrideEv"); // 0x09f8
    private:
        virtual void deferBSDAttach(bool) __asm__(
            "__ZN25IOSkywalkNetworkInterface14deferBSDAttachEb");

    private:
        virtual void nativeSlot0A08() __asm__(
            "__ZN25IOSkywalkNetworkInterface24reportDetailedLinkStatusEPK14if_"
            "link_status");

    private:
        virtual void nativeSlot0A10() __asm__(
            "__ZN25IOSkywalkNetworkInterface13getTSOOptionsEPNS_"
            "19IOSkywalkTSOOptionsE");

    private:
        virtual void
        nativeSlot0A18() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface0Ev");

    private:
        virtual void
        nativeSlot0A20() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface1Ev");

    private:
        virtual void
        nativeSlot0A28() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface2Ev");

    private:
        virtual void
        nativeSlot0A30() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface3Ev");

    private:
        virtual void
        nativeSlot0A38() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface4Ev");

    private:
        virtual void
        nativeSlot0A40() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface5Ev");

    private:
        virtual void
        nativeSlot0A48() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface6Ev");

    private:
        virtual void
        nativeSlot0A50() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface7Ev");

    private:
        virtual void
        nativeSlot0A58() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface8Ev");

    private:
        virtual void
        nativeSlot0A60() __asm__("__ZN25IOSkywalkNetworkInterface35_"
                                 "RESERVEDIOSkywalkNetworkInterface9Ev");

    public:
        virtual IOReturn getHardwareAddress(ether_addr *) __asm__(
            "__"
            "ZN23IO80211SkywalkInterface18getHardwareAddr"
            "essEP10ether_addr"); // 0x0a68
    public:
        virtual IOReturn setHardwareAddress(ether_addr *) __asm__(
            "__"
            "ZN23IO80211SkywalkInterface18setHardwareAddr"
            "essEP10ether_addr"); // 0x0a70
    private:
        virtual void nativeSlot0A78() __asm__(
            "__ZN26IOSkywalkEthernetInterface19setLinkLayerAddressEP10ether_"
            "addr");

    private:
        virtual void
        nativeSlot0A80() __asm__("__"
                                 "ZN26IOSkywalkEthernetInterface24configureMult"
                                 "icastFilterEjPK10ether_addrj");

    private:
        virtual void nativeSlot0A88() __asm__(
            "__ZN26IOSkywalkEthernetInterface21setMulticastAddressesEPK10ether_"
            "addrj");

    private:
        virtual void nativeSlot0A90() __asm__(
            "__ZN26IOSkywalkEthernetInterface25setAllMulticastModeEnableEb");

    private:
        virtual void nativeSlot0A98() __asm__(
            "__ZN23IO80211SkywalkInterface24setPromiscuousModeEnableEbj");

    private:
        virtual void nativeSlot0AA0() __asm__(
            "__ZN26IOSkywalkEthernetInterface20reportNicProxyLimitsE22nicproxy_"
            "limits_info_s");

    private:
        virtual void
        nativeSlot0AA8() __asm__("__"
                                 "ZN26IOSkywalkEthernetInterface20hwConfigNicPr"
                                 "oxyDataEP15nicproxy_info_s");

    private:
        virtual void
        nativeSlot0AB0() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface0Ev");

    private:
        virtual void
        nativeSlot0AB8() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface1Ev");

    private:
        virtual void
        nativeSlot0AC0() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface2Ev");

    private:
        virtual void
        nativeSlot0AC8() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface3Ev");

    private:
        virtual void
        nativeSlot0AD0() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface4Ev");

    private:
        virtual void
        nativeSlot0AD8() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface5Ev");

    private:
        virtual void
        nativeSlot0AE0() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface6Ev");

    private:
        virtual void
        nativeSlot0AE8() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface7Ev");

    private:
        virtual void
        nativeSlot0AF0() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface8Ev");

    private:
        virtual void
        nativeSlot0AF8() __asm__("__ZN26IOSkywalkEthernetInterface36_"
                                 "RESERVEDIOSkywalkEthernetInterface9Ev");

    private:
        virtual void
        nativeSlot0B00() __asm__("__ZN26IOSkywalkEthernetInterface37_"
                                 "RESERVEDIOSkywalkEthernetInterface10Ev");

    private:
        virtual void nativeSlot0B08() __asm__(
            "__ZN23IO80211SkywalkInterface17createPeerManagerEv");

    private:
        virtual void nativeSlot0B10() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface10createPeerEPKhP18IO80211PeerManager");

    public:
        virtual void
        postMessage(unsigned int, void *, unsigned long, bool) __asm__(
            "__ZN23IO80211SkywalkInterface11postMessageEjPvmb"); // 0x0b18
    private:
        virtual void nativeSlot0B20() __asm__(
            "__ZN23IO80211SkywalkInterface20reportDataPathEventsEjPvmb");

    private:
        virtual void
        nativeSlot0B28() __asm__("__"
                                 "ZN23IO80211SkywalkInterface19recordOutputPack"
                                 "etsEP24TxSubmissionDequeueStatsS1_");

    private:
        virtual void nativeSlot0B30() __asm__(
            "__ZN23IO80211SkywalkInterface18recordOutputPacketE17apple80211_"
            "wme_acii");

    private:
        virtual void nativeSlot0B38() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface11logTxPacketEP20IO80211NetworkPacketP2"
            "0PacketSkywalkScratch17apple80211_wme_acb");

    private:
        virtual void nativeSlot0B40() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface21logTxCompletionPacketEP20IO80211Netwo"
            "rkPacketP20PacketSkywalkScratchPh17apple80211_wme_acijbb");

    private:
        virtual void
        nativeSlot0B48() __asm__("__"
                                 "ZN23IO80211SkywalkInterface23recordCompletion"
                                 "PacketsEP24TxCompletionEnqueueStatsS1_");

    private:
        virtual void nativeSlot0B50() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface11inputPacketEP20IO80211NetworkPacketP1"
            "5packet_info_tagP12ether_headerPbb");

    private:
        virtual void nativeSlot0B58() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface24forwardInfraRelayPacketsEP20IO80211Ne"
            "tworkPacketP12ether_header");

    private:
        virtual void nativeSlot0B60() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface21logSkywalkTxReqPacketEP20IO80211Netwo"
            "rkPacketP20PacketSkywalkScratchPh17apple80211_wme_acb");

    public:
        virtual int64_t pendingPackets(unsigned char) __asm__(
            "__ZN23IO80211SkywalkInterface14pendingPacketsEh"); // 0x0b68
    public:
        virtual int64_t packetSpace(unsigned char) __asm__(
            "__ZN23IO80211SkywalkInterface11packetSpaceEh"); // 0x0b70
    public:
        virtual bool isChipInterfaceReady() __asm__(
            "__ZN23IO80211SkywalkInterface20isChipInterfaceReadyEv"); // 0x0b78
    private:
        virtual void nativeSlot0B80() __asm__(
            "__ZN23IO80211SkywalkInterface17isDebounceOnGoingEv");

    public:
        virtual IO80211LinkState linkState() __asm__(
            "__ZN23IO80211SkywalkInterface9linkStateEv"); // 0x0b88
    public:
        virtual void setScanningState(
            unsigned int, bool, apple80211_scan_data *,
            int) __asm__("__"
                         "ZN23IO80211SkywalkInterface16setScanningStateEjbP20ap"
                         "ple80211_scan_datai"); // 0x0b90
    public:
        virtual void setDataPathState(bool) __asm__(
            "__ZN23IO80211SkywalkInterface16setDataPathStateEb"); // 0x0b98
    private:
        virtual void nativeSlot0BA0() __asm__(
            "__ZN23IO80211SkywalkInterface14getScanManagerEv");

    public:
        virtual IO80211Controller *getController() __asm__(
            "__ZN23IO80211SkywalkInterface13getControllerEv"); // 0x0ba8
    private:
        virtual void nativeSlot0BB0() __asm__(
            "__ZN23IO80211SkywalkInterface20updateLinkParametersEP33apple80211_"
            "interface_availability");

    private:
        virtual void nativeSlot0BB8() __asm__(
            "__ZN23IO80211SkywalkInterface26updateInterfaceCoexRiskPctEy");

    private:
        virtual void
        nativeSlot0BC0() __asm__("__ZN23IO80211SkywalkInterface6setLQMEy");

    private:
        virtual void nativeSlot0BC8() __asm__(
            "__ZN23IO80211SkywalkInterface16updateLinkStatusEv");

    private:
        virtual void nativeSlot0BD0() __asm__(
            "__ZN23IO80211SkywalkInterface21updateLinkStatusGatedEv");

    private:
        virtual void nativeSlot0BD8() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface23setInterfaceExtendedCCAE18apple80211_"
            "channelP21apple80211_cca_report");

    private:
        virtual void nativeSlot0BE0() __asm__(
            "__ZN23IO80211SkywalkInterface15setInterfaceCCAE18apple80211_"
            "channeli");

    private:
        virtual void nativeSlot0BE8() __asm__(
            "__ZN23IO80211SkywalkInterface14setInterfaceNFE18apple80211_"
            "channelx");

    private:
        virtual void
        nativeSlot0BF0() __asm__("__"
                                 "ZN23IO80211SkywalkInterface23setInterfaceOFDM"
                                 "DesenseE18apple80211_channelx");

    private:
        virtual void
        nativeSlot0BF8() __asm__("__"
                                 "ZN23IO80211SkywalkInterface17removePacketQueu"
                                 "eEP20IO80211FlowQueueHash");

    private:
        virtual void nativeSlot0C00() __asm__(
            "__ZN23IO80211SkywalkInterface13setDebugFlagsEyj");

    private:
        virtual void
        nativeSlot0C08() __asm__("__ZN23IO80211SkywalkInterface10debugFlagsEv");

    private:
        virtual void nativeSlot0C10() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface24setInterfaceChipCountersEP22apple8021"
            "1_stat_reportP27apple80211_chip_counters_txP33apple80211_chip_"
            "error_counters_txP27apple80211_chip_counters_rx");

    private:
        virtual void nativeSlot0C18() __asm__(
            "__ZN23IO80211SkywalkInterface20setInterfaceMIBdot11EP22apple80211_"
            "stat_reportP50apple80211_ManagementInformationBasedot11_counters");

    private:
        virtual void nativeSlot0C20() __asm__(
            "__ZN23IO80211SkywalkInterface13setFrameStatsEP22apple80211_stat_"
            "reportP25apple80211_frame_counters");

    private:
        virtual void nativeSlot0C28() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface26setInfraSpecificFrameStatsEP22apple80"
            "211_stat_reportP31apple80211_infra_specific_stats");

    private:
        virtual void nativeSlot0C30() __asm__(
            "__ZN23IO80211SkywalkInterface19setRxDataStallStatsEP22apple80211_"
            "stat_reportP31apple80211_rx_data_stall_report");

    private:
        virtual void nativeSlot0C38() __asm__(
            "__ZN23IO80211SkywalkInterface16getWmeTxCountersEPy");

    private:
        virtual void nativeSlot0C40() __asm__(
            "__ZN23IO80211SkywalkInterface21setPeerManagerLogFlagEjjj");

    private:
        virtual void nativeSlot0C48() __asm__(
            "__ZN23IO80211SkywalkInterface13setWoWEnabledEb");

    private:
        virtual void
        nativeSlot0C50() __asm__("__ZN23IO80211SkywalkInterface10wowEnabledEv");

    private:
        virtual void nativeSlot0C58() __asm__(
            "__ZN23IO80211SkywalkInterface13printDataPathEP12userPrintCtx");

    private:
        virtual void nativeSlot0C60() __asm__(
            "__ZN23IO80211SkywalkInterface17getDataQueueDepthEv");

    private:
        virtual void
        nativeSlot0C68() __asm__("__"
                                 "ZN23IO80211SkywalkInterface21findOrCreateFlow"
                                 "QueueE20IO80211FlowQueueHash");

    private:
        virtual void
        nativeSlot0C70() __asm__("__"
                                 "ZN23IO80211SkywalkInterface30findOrCreateFlow"
                                 "QueueWithCacheE20IO80211FlowQueueHashPb");

    private:
        virtual void
        nativeSlot0C78() __asm__("__"
                                 "ZN23IO80211SkywalkInterface21findExistingFlow"
                                 "QueueE20IO80211FlowQueueHash");

    private:
        virtual void
        nativeSlot0C80() __asm__("__"
                                 "ZN23IO80211SkywalkInterface17removePacketQueu"
                                 "eEPK20IO80211FlowQueueHash");

    private:
        virtual void nativeSlot0C88() __asm__(
            "__ZN23IO80211SkywalkInterface17flushPacketQueuesEv");

    private:
        virtual void nativeSlot0C90() __asm__(
            "__ZN23IO80211SkywalkInterface9cachePeerEP10ether_addrPj");

    private:
        virtual void
        nativeSlot0C98() __asm__("__ZN23IO80211SkywalkInterface9shouldLogEy");

    private:
        virtual void nativeSlot0CA0() __asm__(
            "__ZN23IO80211SkywalkInterface9vlogDebugEyPKcP13__va_list_tag");

    private:
        virtual void nativeSlot0CA8() __asm__(
            "__ZN23IO80211SkywalkInterface12vlogDebugBPFEyPKcP13__va_list_tag");

    private:
        virtual void
        nativeSlot0CB0() __asm__("__"
                                 "ZN23IO80211SkywalkInterface24createLinkQualit"
                                 "yMonitorEP11IO80211Peerb");

    private:
        virtual void
        nativeSlot0CB8() __asm__("__"
                                 "ZN23IO80211SkywalkInterface25releaseLinkQuali"
                                 "tyMonitorEP11IO80211Peer");

    private:
        virtual void nativeSlot0CC0() __asm__(
            "__ZN23IO80211SkywalkInterface20getP2PSkywalkPeerMgrEv");

    public:
        virtual bool isCommandProhibited(int) __asm__(
            "__ZN23IO80211SkywalkInterface19isCommandProhibitedEi"); // 0x0cc8
    private:
        virtual void nativeSlot0CD0() __asm__(
            "__ZN23IO80211SkywalkInterface8findPeerER10ether_addr");

    private:
        virtual void
        nativeSlot0CD8() __asm__("__"
                                 "ZN23IO80211SkywalkInterface23setNotificationP"
                                 "ropertyEPK8OSSymbolPK8OSObject");

    private:
        virtual void nativeSlot0CE0() __asm__(
            "__ZN23IO80211SkywalkInterface21getWorkerMatchingDictEP8OSString");

    public:
        virtual bool
        init(IOService *,
             ether_addr *) __asm__("__"
                                   "ZN23IO80211SkywalkInterface4initEP9IOServic"
                                   "eP10ether_addr"); // 0x0ce8
    public:
        virtual bool isInterfaceEnabled() __asm__(
            "__ZN23IO80211SkywalkInterface18isInterfaceEnabledEv"); // 0x0cf0
    public:
        virtual uint64_t getSelfMacAddr() __asm__(
            "__ZN23IO80211SkywalkInterface14getSelfMacAddrEv"); // 0x0cf8
    public:
        virtual IOSkywalkPacketBufferPool *
        getPacketPool(OSString *) __asm__("__"
                                          "ZN23IO80211SkywalkInterface13getPack"
                                          "etPoolEP8OSString"); // 0x0d00
    public:
        virtual CCLogStream *getLogger() const
            __asm__("__ZNK23IO80211SkywalkInterface9getLoggerEv"); // 0x0d08
    private:
        virtual void nativeSlot0D10() __asm__(
            "__ZN23IO80211SkywalkInterface17handleSIOCSIFADDREv");

    private:
        virtual void nativeSlot0D18() __asm__(
            "__ZN23IO80211SkywalkInterface12debugHandlerEP24apple80211_debug_"
            "command");

    private:
        virtual void
        nativeSlot0D20() __asm__("__ZN23IO80211SkywalkInterface9statsDumpEv");

    private:
        virtual void nativeSlot0D28() __asm__(
            "__ZN23IO80211SkywalkInterface19powerOnNotificationEv");

    private:
        virtual void nativeSlot0D30() __asm__(
            "__ZN23IO80211SkywalkInterface20powerOffNotificationEv");

    private:
        virtual void nativeSlot0D38() __asm__(
            "__ZN23IO80211SkywalkInterface15getTxQueueDepthEv");

    private:
        virtual void nativeSlot0D40() __asm__(
            "__ZN23IO80211SkywalkInterface18getRxQueueCapacityEv");

    private:
        virtual void nativeSlot0D48() __asm__(
            "__ZN23IO80211SkywalkInterface15updateRxCounterEy");

    private:
        virtual void nativeSlot0D50() __asm__(
            "__ZN23IO80211SkywalkInterface17getMultiCastQueueEv");

    public:
        virtual int getAssocState() __asm__(
            "__ZN23IO80211SkywalkInterface13getAssocStateEv"); // 0x0d58
    private:
        virtual void nativeSlot0D60() __asm__(
            "__ZN23IO80211SkywalkInterface16notifyQueueStateE17apple80211_wme_"
            "act");

    private:
        virtual void nativeSlot0D68() __asm__(
            "__ZN23IO80211SkywalkInterface13getTxHeadroomEv");

    public:
        virtual OSObject *getRxCompQueue() __asm__(
            "__ZN23IO80211SkywalkInterface14getRxCompQueueEv");

    public:
        virtual OSObject *getTxCompQueue() __asm__(
            "__ZN23IO80211SkywalkInterface14getTxCompQueueEv");

    public:
        virtual OSObject *getTxSubQueue(unsigned int) __asm__(
            "__ZN23IO80211SkywalkInterface13getTxSubQueueE17apple80211_wme_ac");

    public:
        virtual OSObject *getTxPacketPool() __asm__(
            "__ZN23IO80211SkywalkInterface15getTxPacketPoolEv");

    public:
        virtual OSObject *getRxPacketPool() __asm__(
            "__ZN23IO80211SkywalkInterface15getRxPacketPoolEv");

    public:
        virtual IOReturn enableDatapath() __asm__(
            "__ZN23IO80211SkywalkInterface14enableDatapathEv"); // 0x0d98
    public:
        virtual IOReturn disableDatapath() __asm__(
            "__ZN23IO80211SkywalkInterface15disableDatapathEv"); // 0x0da0
    public:
        virtual unsigned int getNumTxQueues() __asm__(
            "__ZN23IO80211SkywalkInterface14getNumTxQueuesEv");

    private:
        virtual void nativeSlot0DB0() __asm__(
            "__ZN23IO80211SkywalkInterface13getLQMSummaryEP22apple80211_lqm_"
            "summary");

    private:
        virtual void nativeSlot0DB8() __asm__(
            "__ZN23IO80211SkywalkInterface16getEventPipeSizeEv");

    private:
        virtual void
        nativeSlot0DC0() __asm__("__"
                                 "ZN23IO80211SkywalkInterface15createEventPipeE"
                                 "P20IO80211APIUserClient");

    private:
        virtual void
        nativeSlot0DC8() __asm__("__"
                                 "ZN23IO80211SkywalkInterface16destroyEventPipe"
                                 "EP20IO80211APIUserClient");

    private:
        virtual void
        nativeSlot0DD0() __asm__("__"
                                 "ZN23IO80211SkywalkInterface17setUserBufferInf"
                                 "oEP18IOMemoryDescriptory");

    private:
        virtual void nativeSlot0DD8() __asm__(
            "__ZN23IO80211SkywalkInterface15postMessageIOUCEPKcjPvm");

    private:
        virtual void nativeSlot0DE0() __asm__(
            "__ZN23IO80211SkywalkInterface16isIOUCPipeOpenedEv");

    private:
        virtual void nativeSlot0DE8() __asm__(
            "__ZN23IO80211SkywalkInterface9getRingMDEP20IO80211APIUserClienty");

    private:
        virtual void nativeSlot0DF0() __asm__(
            "__ZN23IO80211SkywalkInterface10attachPeerEP10ether_addr");

    private:
        virtual void nativeSlot0DF8() __asm__(
            "__ZN23IO80211SkywalkInterface10detachPeerEP10ether_addr");

    private:
        virtual void nativeSlot0E00() __asm__(
            "__ZN23IO80211SkywalkInterface21setDebugTrafficReportEb");

    private:
        virtual void nativeSlot0E08() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface25getDataPathInterfaceStatsEP36apple802"
            "11_data_path_interface_stats");

    private:
        virtual void nativeSlot0E10() __asm__(
            "__ZN23IO80211SkywalkInterface20getDataPathPeerStatsEP31apple80211_"
            "data_path_peer_stats");

    private:
        virtual void nativeSlot0E18() __asm__(
            "__ZN23IO80211SkywalkInterface22getLastQueuePacketTimeEP10ether_"
            "addr");

    private:
        virtual void
        nativeSlot0E20() __asm__("__"
                                 "ZN23IO80211SkywalkInterface32getLastRxUnicast"
                                 "LinkActivityTimeEP10ether_addr");

    private:
        virtual void nativeSlot0E28() __asm__(
            "__"
            "ZN23IO80211SkywalkInterface24updateInterfaceDataStatsEP36apple8021"
            "1_data_path_interface_stats");

    private:
        virtual void nativeSlot0E30() __asm__(
            "__ZN23IO80211SkywalkInterface19updatePeerDataStatsEP31apple80211_"
            "data_path_peer_stats");

    private:
        virtual void nativeSlot0E38() __asm__(
            "__ZN23IO80211SkywalkInterface12logTxLatencyEPhjy");

    private:
        virtual void nativeSlot0E40() __asm__(
            "__ZN23IO80211SkywalkInterface12logRxLatencyEjy");

    private:
        virtual void nativeSlot0E48() __asm__(
            "__ZN23IO80211SkywalkInterface20getNClearTxRxLatencyEP25apple80211_"
            "latency_all_acS1_");

    private:
        virtual void nativeSlot0E50() __asm__(
            "__ZN23IO80211SkywalkInterface18getLastTxTimeStampERy");

    private:
        virtual void nativeSlot0E58() __asm__(
            "__ZN23IO80211SkywalkInterface18getLastRxTimeStampERy");

    private:
        virtual void nativeSlot0E60() __asm__(
            "__ZN23IO80211SkywalkInterface12syncDPSStatsEP26apple82011_"
            "postMessage_dps");

    private:
        uint8_t nativeStorage_[0x128 - sizeof(IOService)];
};

static_assert(sizeof(IOService) == 0x88, "25G332 service prefix size");
static_assert(sizeof(IO80211SkywalkInterface) == 0x128,
              "25G332 wireless interface size");

class IO80211InfraInterface : public IO80211SkywalkInterface
{
    OSDeclareAbstractStructors(IO80211InfraInterface) public
        : bool init() override;
        void free() override;
        IOReturn configureReport(IOReportChannelList *, unsigned int, void *,
                                 void *) override;
        IOReturn updateReport(IOReportChannelList *, unsigned int, void *,
                              void *) override;
        bool start(IOService *) override;
        void stop(IOService *) override;
        IOReturn setPowerState(unsigned long, IOService *) override;

    private:
        virtual void nativeSlot08E0() __asm__(
            "__ZN21IO80211InfraInterface26initBSDInterfaceParametersEP18ifnet_"
            "init_eparamsPP11sockaddr_dl") override;

    private:
        virtual void nativeSlot08E8() __asm__(
            "__ZN21IO80211InfraInterface19prepareBSDInterfaceEP7__ifnetj")
            override;

    private:
        virtual void nativeSlot0910() __asm__(
            "__ZN21IO80211InfraInterface17processBSDCommandEP7__ifnetjPv")
            override;

    public:
        virtual int32_t setInterfaceEnable(bool) __asm__(
            "__ZN21IO80211InfraInterface18setInterfaceEnableEb")
            override; // 0x0930
    public:
        virtual uint32_t getHardwareAssists() __asm__(
            "__ZN21IO80211InfraInterface18getHardwareAssistsEv")
            override; // 0x0990
    private:
        virtual void nativeSlot09E0() __asm__(
            "__ZN21IO80211InfraInterface6bpfTapEjj") override;

    private:
        virtual void nativeSlot0AA8() __asm__(
            "__ZN21IO80211InfraInterface20hwConfigNicProxyDataEP15nicproxy_"
            "info_s") override;

    public:
        virtual void postMessage(
            unsigned int, void *, unsigned long,
            bool) __asm__("__ZN21IO80211InfraInterface11postMessageEjPvmb")
            override; // 0x0b18
    private:
        virtual void
        nativeSlot0B28() __asm__("__"
                                 "ZN21IO80211InfraInterface19recordOutputPacket"
                                 "sEP24TxSubmissionDequeueStatsS1_") override;

    private:
        virtual void nativeSlot0B38() __asm__(
            "__"
            "ZN21IO80211InfraInterface11logTxPacketEP20IO80211NetworkPacketP20P"
            "acketSkywalkScratch17apple80211_wme_acb") override;

    private:
        virtual void nativeSlot0B40() __asm__(
            "__"
            "ZN21IO80211InfraInterface21logTxCompletionPacketEP20IO80211Network"
            "PacketP20PacketSkywalkScratchPh17apple80211_wme_acijbb") override;

    private:
        virtual void nativeSlot0B48() __asm__(
            "__"
            "ZN21IO80211InfraInterface23recordCompletionPacketsEP24TxCompletion"
            "EnqueueStatsS1_") override;

    private:
        virtual void nativeSlot0B50() __asm__(
            "__"
            "ZN21IO80211InfraInterface11inputPacketEP20IO80211NetworkPacketP15p"
            "acket_info_tagP12ether_headerPbb") override;

    public:
        virtual int64_t pendingPackets(unsigned char) __asm__(
            "__ZN21IO80211InfraInterface14pendingPacketsEh") override; // 0x0b68
    public:
        virtual int64_t packetSpace(unsigned char) __asm__(
            "__ZN21IO80211InfraInterface11packetSpaceEh") override; // 0x0b70
    private:
        virtual void nativeSlot0B80() __asm__(
            "__ZN21IO80211InfraInterface17isDebounceOnGoingEv") override;

    public:
        virtual IO80211LinkState linkState() __asm__(
            "__ZN21IO80211InfraInterface9linkStateEv") override; // 0x0b88
    public:
        virtual void setScanningState(
            unsigned int, bool, apple80211_scan_data *,
            int) __asm__("__"
                         "ZN21IO80211InfraInterface16setScanningStateEjbP20appl"
                         "e80211_scan_datai") override; // 0x0b90
    public:
        virtual void setDataPathState(bool) __asm__(
            "__ZN21IO80211InfraInterface16setDataPathStateEb")
            override; // 0x0b98
    private:
        virtual void nativeSlot0BA0() __asm__(
            "__ZN21IO80211InfraInterface14getScanManagerEv") override;

    private:
        virtual void nativeSlot0BB0() __asm__(
            "__ZN21IO80211InfraInterface20updateLinkParametersEP33apple80211_"
            "interface_availability") override;

    private:
        virtual void nativeSlot0BB8() __asm__(
            "__ZN21IO80211InfraInterface26updateInterfaceCoexRiskPctEy")
            override;

    private:
        virtual void nativeSlot0BC0() __asm__(
            "__ZN21IO80211InfraInterface6setLQMEy") override;

    private:
        virtual void nativeSlot0BC8() __asm__(
            "__ZN21IO80211InfraInterface16updateLinkStatusEv") override;

    private:
        virtual void nativeSlot0BD0() __asm__(
            "__ZN21IO80211InfraInterface21updateLinkStatusGatedEv") override;

    private:
        virtual void nativeSlot0BD8() __asm__(
            "__ZN21IO80211InfraInterface23setInterfaceExtendedCCAE18apple80211_"
            "channelP21apple80211_cca_report") override;

    private:
        virtual void nativeSlot0BE0() __asm__(
            "__ZN21IO80211InfraInterface15setInterfaceCCAE18apple80211_"
            "channeli") override;

    private:
        virtual void nativeSlot0BE8() __asm__(
            "__ZN21IO80211InfraInterface14setInterfaceNFE18apple80211_channelx")
            override;

    private:
        virtual void nativeSlot0BF0() __asm__(
            "__ZN21IO80211InfraInterface23setInterfaceOFDMDesenseE18apple80211_"
            "channelx") override;

    private:
        virtual void nativeSlot0C00() __asm__(
            "__ZN21IO80211InfraInterface13setDebugFlagsEyj") override;

    private:
        virtual void nativeSlot0C08() __asm__(
            "__ZN21IO80211InfraInterface10debugFlagsEv") override;

    private:
        virtual void nativeSlot0C10() __asm__(
            "__"
            "ZN21IO80211InfraInterface24setInterfaceChipCountersEP22apple80211_"
            "stat_reportP27apple80211_chip_counters_txP33apple80211_chip_error_"
            "counters_txP27apple80211_chip_counters_rx") override;

    private:
        virtual void nativeSlot0C18() __asm__(
            "__ZN21IO80211InfraInterface20setInterfaceMIBdot11EP22apple80211_"
            "stat_reportP50apple80211_ManagementInformationBasedot11_counters")
            override;

    private:
        virtual void nativeSlot0C20() __asm__(
            "__ZN21IO80211InfraInterface13setFrameStatsEP22apple80211_stat_"
            "reportP25apple80211_frame_counters") override;

    private:
        virtual void nativeSlot0C28() __asm__(
            "__"
            "ZN21IO80211InfraInterface26setInfraSpecificFrameStatsEP22apple8021"
            "1_stat_reportP31apple80211_infra_specific_stats") override;

    private:
        virtual void nativeSlot0C30() __asm__(
            "__ZN21IO80211InfraInterface19setRxDataStallStatsEP22apple80211_"
            "stat_reportP31apple80211_rx_data_stall_report") override;

    private:
        virtual void nativeSlot0C38() __asm__(
            "__ZN21IO80211InfraInterface16getWmeTxCountersEPy") override;

    private:
        virtual void nativeSlot0C40() __asm__(
            "__ZN21IO80211InfraInterface21setPeerManagerLogFlagEjjj") override;

    private:
        virtual void nativeSlot0C48() __asm__(
            "__ZN21IO80211InfraInterface13setWoWEnabledEb") override;

    private:
        virtual void nativeSlot0C50() __asm__(
            "__ZN21IO80211InfraInterface10wowEnabledEv") override;

    private:
        virtual void
        nativeSlot0CB0() __asm__("__"
                                 "ZN21IO80211InfraInterface24createLinkQualityM"
                                 "onitorEP11IO80211Peerb") override;

    private:
        virtual void
        nativeSlot0CB8() __asm__("__"
                                 "ZN21IO80211InfraInterface25releaseLinkQuality"
                                 "MonitorEP11IO80211Peer") override;

    public:
        virtual int getAssocState() __asm__(
            "__ZN21IO80211InfraInterface13getAssocStateEv") override; // 0x0d58
    private:
        virtual void nativeSlot0DB0() __asm__(
            "__ZN21IO80211InfraInterface13getLQMSummaryEP22apple80211_lqm_"
            "summary") override;

    public:
        virtual bool setLinkState(
            IO80211LinkState, unsigned int, bool, unsigned int,
            unsigned int) __asm__("__"
                                  "ZN21IO80211InfraInterface12setLinkStateE16IO"
                                  "80211LinkStatejbjj"); // 0x0e68
    public:
        virtual IOReturn setLinkStateInternal(
            IO80211LinkState, unsigned int, bool, unsigned int,
            unsigned int) __asm__("__"
                                  "ZN21IO80211InfraInterface20setLinkStateInter"
                                  "nalE16IO80211LinkStatejbjj"); // 0x0e70
    public:
        virtual void setCurrentApAddress(ether_addr *) __asm__(
            "__"
            "ZN21IO80211InfraInterface19setCurrentApAddre"
            "ssEP10ether_addr"); // 0x0e78
    private:
        virtual void nativeSlot0E80() __asm__(
            "__ZN21IO80211InfraInterface21setWCL_ADVISORTY_INFOEP28apple80211_"
            "wcl_advisory_info");

    private:
        virtual void
        nativeSlot0E88() __asm__("__ZN21IO80211InfraInterface20getWCL_TX_RX_"
                                 "LATENCYEP28apple80211_wcl_tx_rx_latency");

    private:
        virtual void nativeSlot0E90() __asm__(
            "__ZN21IO80211InfraInterface24setWCL_LINK_STATE_"
            "UPDATEEP32apple80211_wcl_update_link_state");

    private:
        virtual void nativeSlot0E98() __asm__(
            "__ZN21IO80211InfraInterface13createLQMDataEv");

    public:
        virtual IOReturn setMacAddress(void *) = 0; // 0xea0
    private:
        uint8_t nativeInfraStorage_[0x130 - sizeof(IO80211SkywalkInterface)];
};

static_assert(sizeof(IO80211InfraInterface) == 0x130,
              "25G332 infrastructure interface size");

class IO80211InfraProtocol : public IO80211InfraInterface
{
    OSDeclareAbstractStructors(IO80211InfraProtocol) public:
// Native wrappers pass one request pointer and return an IOReturn. The
// dispatcher interprets only explicitly supported, versioned request layouts.
#define SIMPLEATH_INFRA_OPERATION(name, slot) virtual IOReturn name(void *) = 0;
#include "TahoeInfraOperations.inc"
#undef SIMPLEATH_INFRA_OPERATION
};

static_assert(sizeof(IO80211InfraProtocol) == 0x130,
              "25G332 infrastructure protocol size");
#endif
