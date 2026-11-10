#include "SimpleATHInfraProtocol.hpp"
#include "SimpleATHTahoeController.hpp"
#include <IOKit/80211/apple80211_ioctl.h>
#include <IOKit/80211/apple80211_var.h>
#include <cstring>
#include <libkern/c++/OSString.h>

namespace
{
    extern "C" void
    wirelessPost(IO80211Controller *, IO80211SkywalkInterface *, unsigned int,
                 void *, unsigned long,
                 bool) __asm__("__"
                               "ZN17IO80211Controller11postMessageEP23IO80211Sk"
                               "ywalkInterfacejPvmb");
    constexpr unsigned int kSetMac = 0xea0;
    constexpr unsigned int kEnable = 1;
    constexpr unsigned int kDisable = 2;
    constexpr unsigned int kEnablePackets = 3;
    constexpr unsigned int kDisablePackets = 4;
    constexpr unsigned int kPollMilliseconds = 10;
    constexpr unsigned int kScanResultEvent = 201;
    constexpr unsigned int kScanDoneEvent = 237;
    constexpr unsigned int kDriverAvailableEvent = 55;

    template <typename T> T *prefix(OSObject *object)
    {
        T *result = nullptr;
        static_assert(sizeof(result) == sizeof(object), "native pointer width");
        memcpy(&result, &object, sizeof(result));
        return result;
    }

    template <typename T> void put(uint8_t *bytes, size_t offset, T value)
    {
        memcpy(bytes + offset, &value, sizeof(value));
    }
} // namespace

SimpleATHInfraProtocol::MetaClass SimpleATHInfraProtocol::gMetaClass;
const OSMetaClass *const SimpleATHInfraProtocol::metaClass =
    &SimpleATHInfraProtocol::gMetaClass;
constexpr const OSMetaClass *SimpleATHInfraProtocol::superClass;

SimpleATHInfraProtocol::SimpleATHInfraProtocol(const OSMetaClass *meta)
    : IO80211InfraProtocol(meta)
{
}

SimpleATHInfraProtocol::~SimpleATHInfraProtocol() = default;

const OSMetaClass *SimpleATHInfraProtocol::getMetaClass() const
{
    return &gMetaClass;
}

SimpleATHInfraProtocol::MetaClass::MetaClass() noexcept
    : OSMetaClass("SimpleATHInfraProtocol", SimpleATHInfraProtocol::superClass,
                  sizeof(SimpleATHInfraProtocol))
{
}

OSDefineDefaultStructors(SimpleATHInfraProtocol, IO80211InfraProtocol)

    bool SimpleATHInfraProtocol::initialize(
        SimpleATHTahoeController *controller)
{
    if (controller == nullptr || !IO80211InfraInterface::init())
    {
        return false;
    }
    controller_ = controller;
    IOEthernetAddress mac {};
    if (controller_->getHardwareAddress(&mac) != kIOReturnSuccess)
    {
        return false;
    }
    ether_addr address {};
    memcpy(&address, &mac, sizeof(address));
    if (!IO80211SkywalkInterface::init(controller_, &address))
    {
        return false;
    }
    setInterfaceRole(1);
    setInterfaceId(1);
    return true;
}

bool SimpleATHInfraProtocol::start(IOService *provider)
{
    if (provider != controller_ || controller_ == nullptr)
    {
        return false;
    }
    stopping_ = false;
    auto *loop = getWorkLoop();
    gate_ = IOCommandGate::commandGate(this);
    timer_ = IOTimerEventSource::timerEventSource(
        this, &SimpleATHInfraProtocol::tick);
    if (loop == nullptr || gate_ == nullptr || timer_ == nullptr)
    {
        return false;
    }
    if (loop->addEventSource(gate_) != kIOReturnSuccess)
    {
        return false;
    }
    gateAdded_ = true;
    if (loop->addEventSource(timer_) != kIOReturnSuccess)
    {
        return false;
    }
    timerAdded_ = true;
    // Even a partial native start is unwound while the controller's work
    // queue, capture streams and fault reporter remain alive.
    parentStarted_ = true;
    if (!IO80211InfraInterface::start(provider))
    {
        return false;
    }
    const IOReturn result = packets_.start(this, controller_);
    if (result != kIOReturnSuccess)
    {
        setProperty("SimpleATHNativePacketError",
                    static_cast<unsigned long long>(result), 32);
        return false;
    }
    timer_->setTimeoutMS(kPollMilliseconds);
    return true;
}

void SimpleATHInfraProtocol::stop(IOService *provider)
{
    if (gateAdded_)
    {
        (void)gate_->runAction(&SimpleATHInfraProtocol::stopAction);
    }
    else
    {
        shutdown();
    }
    if (parentStarted_)
    {
        parentStarted_ = false;
        IO80211InfraInterface::stop(provider);
    }
    auto *loop = getWorkLoop();
    if (timer_ != nullptr)
    {
        if (timerAdded_ && loop != nullptr)
        {
            loop->removeEventSource(timer_);
        }
        timerAdded_ = false;
        timer_->release();
        timer_ = nullptr;
    }
    if (gate_ != nullptr)
    {
        if (gateAdded_ && loop != nullptr)
        {
            loop->removeEventSource(gate_);
        }
        gateAdded_ = false;
        gate_->release();
        gate_ = nullptr;
    }
    controller_ = nullptr;
}

void SimpleATHInfraProtocol::free()
{
    if (controller_ != nullptr)
    {
        stop(controller_);
    }
    IO80211InfraInterface::free();
}

IOWorkLoop *SimpleATHInfraProtocol::getWorkLoop() const
{
    return controller_ != nullptr ? controller_->getWorkQueue() : nullptr;
}

void SimpleATHInfraProtocol::shutdown()
{
    if (stopping_)
    {
        return;
    }
    stopping_ = true;
    if (timer_ != nullptr)
    {
        timer_->cancelTimeout();
        timer_->disable();
    }
    if (scanGeneration_ != 0 && controller_ != nullptr)
    {
        (void)controller_->scanCancel(scanGeneration_);
        finishScan(true);
    }
    packets_.stop();
}

IOReturn SimpleATHInfraProtocol::stopAction(OSObject *owner, void *, void *,
                                            void *, void *)
{
    auto *interface = OSDynamicCast(SimpleATHInfraProtocol, owner);
    if (interface == nullptr)
    {
        return kIOReturnBadArgument;
    }
    interface->shutdown();
    return kIOReturnSuccess;
}

IOReturn SimpleATHInfraProtocol::requestAction(OSObject *owner, void *operation,
                                               void *data, void *, void *)
{
    auto *interface = OSDynamicCast(SimpleATHInfraProtocol, owner);
    if (interface == nullptr || operation == nullptr || interface->stopping_)
    {
        return kIOReturnNotReady;
    }
    return interface->requestGated(
        *static_cast<const unsigned int *>(operation), data);
}

IOReturn SimpleATHInfraProtocol::request(unsigned int operation, void *data)
{
    if (!gateAdded_)
    {
        return kIOReturnNotReady;
    }
    return gate_->runAction(&SimpleATHInfraProtocol::requestAction, &operation,
                            data);
}

#define SIMPLEATH_INFRA_OPERATION(name, slot)                                  \
    IOReturn SimpleATHInfraProtocol::name(void *data)                          \
    {                                                                          \
        return request(slot, data);                                            \
    }
#include "TahoeInfraOperations.inc"
#undef SIMPLEATH_INFRA_OPERATION

IOReturn SimpleATHInfraProtocol::enable(unsigned int)
{
    return request(kEnable, nullptr);
}

IOReturn SimpleATHInfraProtocol::disable(unsigned int)
{
    return request(kDisable, nullptr);
}

IOReturn SimpleATHInfraProtocol::enableDatapath()
{
    return request(kEnablePackets, nullptr);
}

IOReturn SimpleATHInfraProtocol::disableDatapath()
{
    return request(kDisablePackets, nullptr);
}

IOReturn SimpleATHInfraProtocol::setMacAddress(void *addresses)
{
    return request(kSetMac, addresses);
}

IOReturn SimpleATHInfraProtocol::setHardwareAddress(ether_addr *address)
{
    return request(kSetMac, address);
}

IOReturn SimpleATHInfraProtocol::getHardwareAddress(ether_addr *out)
{
    if (out == nullptr || controller_ == nullptr)
    {
        return kIOReturnBadArgument;
    }
    IOEthernetAddress address {};
    const auto result = controller_->getHardwareAddress(&address);
    if (result == kIOReturnSuccess)
    {
        memcpy(out, &address, sizeof(*out));
    }
    return result;
}

uint64_t SimpleATHInfraProtocol::getSelfMacAddr()
{
    // Native registerInfraEthernetInterface consumes the MAC VALUE in RAX,
    // not a pointer. Its low six bytes are the link-layer address.
    uint64_t value = 0;
    ether_addr address {};
    if (getHardwareAddress(&address) == kIOReturnSuccess)
    {
        memcpy(&value, &address, sizeof(address));
    }
    return value;
}

OSObject *SimpleATHInfraProtocol::getRxCompQueue()
{
    return packets_.rxCompletion();
}

OSObject *SimpleATHInfraProtocol::getTxCompQueue()
{
    return packets_.txCompletion();
}

OSObject *SimpleATHInfraProtocol::getTxSubQueue(unsigned int category)
{
    return category < 4 ? packets_.txSubmission() : nullptr;
}

OSObject *SimpleATHInfraProtocol::getTxPacketPool()
{
    return packets_.txPool();
}

OSObject *SimpleATHInfraProtocol::getRxPacketPool()
{
    return packets_.rxPool();
}

unsigned int SimpleATHInfraProtocol::getNumTxQueues()
{
    return packets_.registered() ? 1 : 0;
}

IOSkywalkPacketBufferPool *SimpleATHInfraProtocol::getPacketPool(OSString *name)
{
    if (name == nullptr)
    {
        return nullptr;
    }
    if (name->isEqualTo("SimpleATH-TX"))
    {
        return prefix<IOSkywalkPacketBufferPool>(packets_.txPool());
    }
    if (name->isEqualTo("SimpleATH-RX"))
    {
        return prefix<IOSkywalkPacketBufferPool>(packets_.rxPool());
    }
    return nullptr;
}

CCLogStream *SimpleATHInfraProtocol::getLogger() const
{
    return controller_ != nullptr ? controller_->getLogger() : nullptr;
}

uint32_t SimpleATHInfraProtocol::getHardwareAssists()
{
    return 0;
}

uint32_t SimpleATHInfraProtocol::getMaxTransferUnit()
{
    return 1500;
}

bool SimpleATHInfraProtocol::isChipInterfaceReady()
{
    simpleath::tahoe::WirelessSnapshot state {};
    return controller_ != nullptr &&
           controller_->radioSnapshot(state) == kIOReturnSuccess &&
           state.radioAvailable && state.powered && !state.rfKillBlocked;
}

bool SimpleATHInfraProtocol::isCommandProhibited(int command)
{
    return stopping_ || controller_ == nullptr ||
           controller_->isCommandProhibited(command);
}

int SimpleATHInfraProtocol::getAssocState()
{
    simpleath::tahoe::WirelessSnapshot state {};
    return controller_ != nullptr &&
                   controller_->radioSnapshot(state) == kIOReturnSuccess &&
                   state.associated
               ? APPLE80211_S_RUN
               : APPLE80211_S_INIT;
}

IO80211LinkState SimpleATHInfraProtocol::linkState()
{
    simpleath::tahoe::WirelessSnapshot state {};
    const bool up = controller_ != nullptr &&
                    controller_->radioSnapshot(state) == kIOReturnSuccess &&
                    state.radioAvailable && state.powered &&
                    !state.rfKillBlocked && state.associated &&
                    state.controlledPortOpen;
    return static_cast<IO80211LinkState>(up ? 2 : 1);
}

IOReturn SimpleATHInfraProtocol::requestGated(unsigned int operation,
                                              void *data)
{
    if (controller_ == nullptr)
    {
        return kIOReturnNotReady;
    }
    if (operation == kEnable)
    {
        return controller_->radioPower(true);
    }
    if (operation == kDisable)
    {
        packets_.disable();
        if (scanGeneration_ != 0)
        {
            (void)controller_->scanCancel(scanGeneration_);
            finishScan(true);
        }
        return controller_->radioPower(false);
    }
    if (operation == kEnablePackets)
    {
        if (!isChipInterfaceReady())
        {
            return kIOReturnNotReady;
        }
        const auto result = packets_.enable();
        dataRequested_ = result == kIOReturnSuccess;
        return result;
    }
    if (operation == kDisablePackets)
    {
        dataRequested_ = false;
        packets_.disable();
        return kIOReturnSuccess;
    }
    if (data == nullptr)
    {
        return kIOReturnBadArgument;
    }
    if (operation == kSetMac)
    {
        uint8_t address[6] {};
        memcpy(address, data, sizeof(address));
        return controller_->radioMac(address);
    }
    if (operation == 0x12c8)
    {
        return beginScan(data);
    }
    if (operation == 0x12a0)
    {
        if (scanGeneration_ == 0)
        {
            return kIOReturnNotFound;
        }
        const auto result = controller_->scanCancel(scanGeneration_);
        if (result == kIOReturnSuccess)
        {
            finishScan(true);
        }
        return result;
    }
    if (operation == 0x1270 || operation == 0x12b8)
    {
        packets_.disable();
        return controller_->stationLeave(3);
    }
    simpleath::tahoe::WirelessSnapshot state {};
    const auto result = controller_->radioSnapshot(state);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    if (operation == 0xfe8)
    {
        auto *bytes = static_cast<uint8_t *>(data);
        const uint32_t version = 1;
        memcpy(bytes, &version, sizeof(version));
        memcpy(bytes + 4, state.permanentMac, 6);
        memset(bytes + 10, 0, 2);
        return kIOReturnSuccess;
    }
    if (operation == 0xea8)
    {
        if (state.channel < 1 || state.channel > 14)
        {
            return kIOReturnNotReady;
        }
        auto *out = static_cast<apple80211_channel_data *>(data);
        *out = {};
        out->version = APPLE80211_VERSION;
        out->channel.version = APPLE80211_VERSION;
        out->channel.channel = state.channel;
        out->channel.flags = APPLE80211_C_FLAG_2GHZ | APPLE80211_C_FLAG_20MHZ;
        return kIOReturnSuccess;
    }
    if (operation == 0xec8)
    {
        auto *out = static_cast<apple80211_opmode_data *>(data);
        out->version = APPLE80211_VERSION;
        out->op_mode = APPLE80211_M_STA;
        return kIOReturnSuccess;
    }
    if (operation == 0xed0)
    {
        if (!state.associated)
        {
            return kIOReturnNotReady;
        }
        auto *out = static_cast<apple80211_rssi_data *>(data);
        *out = {};
        out->version = APPLE80211_VERSION;
        out->num_radios = 1;
        out->rssi_unit = APPLE80211_UNIT_DBM;
        out->rssi[0] = state.rssiDbm;
        out->aggregate_rssi = state.rssiDbm;
        return kIOReturnSuccess;
    }
    // Optional operations are explicitly rejected rather than acknowledging
    // unsupported offloads, VHT/HE, 5/6 GHz or unimplemented native requests.
    // Required association/PMK/AWDL operations remain tracked in the P0 TODO.
    setProperty("SimpleATHLastUnsupportedOperation", operation, 32);
    return kIOReturnUnsupported;
}

IOReturn SimpleATHInfraProtocol::beginScan(void *data)
{
    if (scanGeneration_ != 0)
    {
        return kIOReturnBusy;
    }
    simpleath::tahoe::ScanFilter filter {};
    // WCL owns this fixed-size native request during the synchronous call.
    if (!simpleath::tahoe::decodeScan(static_cast<const uint8_t *>(data),
                                      0x1550, filter))
    {
        return kIOReturnBadArgument;
    }
    simpleath::tahoe::WirelessSnapshot state {};
    const auto status = controller_->radioSnapshot(state);
    if (status != kIOReturnSuccess)
    {
        return status;
    }
    uint64_t generation = 0;
    const auto result = controller_->scanStart(generation);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    scan_ = filter;
    scanEpoch_ = state.epoch;
    scanGeneration_ = generation;
    return kIOReturnSuccess;
}

void SimpleATHInfraProtocol::emit(unsigned int event, void *bytes,
                                  size_t length)
{
    wirelessPost(controller_, this, event, bytes, length, true);
}

void SimpleATHInfraProtocol::finishScan(bool canceled)
{
    if (scanGeneration_ == 0)
    {
        return;
    }
    IOReturn status = canceled ? kIOReturnAborted : kIOReturnSuccess;
    if (!canceled)
    {
        // Bounded copied results; never expose live ScanCache or DMA memory.
        for (size_t i = 0; i <= simpleath::ieee80211::ScanCache::kCapacity; ++i)
        {
            simpleath::ieee80211::NativeBssSnapshot bss {};
            const auto result = controller_->scanNext(scanGeneration_, bss);
            if (result == kIOReturnNotFound)
            {
                break;
            }
            if (result != kIOReturnSuccess)
            {
                status = result;
                break;
            }
            if (i == simpleath::ieee80211::ScanCache::kCapacity)
            {
                status = kIOReturnOverrun;
                break;
            }
            if (!simpleath::tahoe::scanMatches(scan_, bss.bssid.bytes, bss.ssid,
                                               bss.ssidLength, bss.channel))
            {
                continue;
            }
            uint8_t message[simpleath::tahoe::kScanMessageBytes] {};
            const size_t length =
                simpleath::tahoe::encodeScanBss(bss, message, sizeof(message));
            if (length == 0)
            {
                status = kIOReturnBadArgument;
                break;
            }
            emit(kScanResultEvent, message, length);
        }
    }
    scanGeneration_ = 0;
    scanEpoch_ = 0;
    scan_ = {};
    emit(kScanDoneEvent, &status, sizeof(status));
}

void SimpleATHInfraProtocol::tick(OSObject *owner, IOTimerEventSource *)
{
    auto *interface = OSDynamicCast(SimpleATHInfraProtocol, owner);
    if (interface != nullptr && !interface->stopping_)
    {
        interface->poll();
    }
}

void SimpleATHInfraProtocol::poll()
{
    simpleath::tahoe::WirelessSnapshot state {};
    const auto result = controller_->radioSnapshot(state);
    const bool live = result == kIOReturnSuccess;
    const bool available =
        live && state.radioAvailable && state.powered && !state.rfKillBlocked;
    if (!live || state.epoch != lastEpoch_)
    {
        packets_.disable();
        if (scanGeneration_ != 0 && (!live || scanEpoch_ != state.epoch))
        {
            finishScan(true);
        }
        lastEpoch_ = live ? state.epoch : 0;
    }
    if (available != available_)
    {
        available_ = available;
        uint8_t availability[0xf8] {};
        put<uint32_t>(availability, 0, 1);
        put<uint32_t>(availability, 8, available ? 1U : 0U);
        emit(kDriverAvailableEvent, availability, sizeof(availability));
    }
    const bool link = available && state.associated && state.controlledPortOpen;
    if (link != linked_)
    {
        linked_ = link;
        (void)setLinkState(static_cast<IO80211LinkState>(link ? 2 : 1), 0,
                           false, 0, 0);
    }
    for (size_t i = 0;
         i < simpleath::tahoe::TahoeWirelessTransport::kEventCapacity; ++i)
    {
        simpleath::tahoe::WirelessEvent event {};
        uint64_t epoch = 0;
        if (controller_->nextRadioEvent(event, epoch) != kIOReturnSuccess)
        {
            break;
        }
        if (event == simpleath::tahoe::WirelessEvent::ScanFinished &&
            epoch == scanEpoch_)
        {
            finishScan(false);
        }
    }
    if (available && dataRequested_)
    {
        (void)packets_.enable();
    }
    else
    {
        packets_.disable();
    }
    packets_.poll();
    timer_->setTimeoutMS(kPollMilliseconds);
}
