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

#include "SimpleATHInfraProtocol.hpp"
#include "NativeWirelessOwner.hpp"
#include "SimpleATHTahoeController.hpp"
#include "TahoeApple80211Values.hpp"
#include "TahoeCapabilities.hpp"
#include "TahoeDataPathAdmission.hpp"
#include <kern/clock.h>
#include <libkern/c++/OSString.h>
#include <stdint.h>
#include <string.h>

namespace
{
    extern "C" void
    wirelessPost(IO80211Controller *, IO80211SkywalkInterface *, unsigned int,
                 void *, unsigned long,
                 bool) __asm__("__"
                               "ZN17IO80211Controller11postMessageEP23IO80211Sk"
                               "ywalkInterfacejPvmb");
    constexpr unsigned int kSetMac = 0xea0;
    constexpr unsigned int kGetPowerSave = 0x0eb0;
    constexpr unsigned int kGetNss = 0x0fe0;
    constexpr unsigned int kEnable = 1;
    constexpr unsigned int kDisable = 2;
    constexpr unsigned int kEnablePackets = 3;
    constexpr unsigned int kDisablePackets = 4;
    constexpr unsigned int kPollMilliseconds = 10;
    constexpr unsigned int kScanResultEvent = 201;
    constexpr unsigned int kScanDoneEvent = 237;
    constexpr unsigned int kDriverAvailableEvent = 55;
    constexpr unsigned int kJoinTimeoutSeconds = 30;

    bool nativePacketAdmission(const simpleath::tahoe::WirelessSnapshot &state,
                               bool requested, uint64_t requestEpoch)
    {
        const simpleath::tahoe::NativeDataPathAdmission evidence {
            requestEpoch,
            state.epoch,
            state.associationGeneration,
            requested,
            state.radioAvailable,
            state.powered,
            state.rfKillBlocked,
            state.associated,
            state.controlledPortOpen,
            state.associatedBeaconObserved,
        };
        return simpleath::tahoe::mayEnableNativeDataPath(evidence);
    }

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
    if (timer_->setTimeoutMS(kPollMilliseconds) != kIOReturnSuccess)
    {
        // A running interface without polling cannot retire WCL joins,
        // scan completions or a vanished provider. Fail this partial start,
        // and ask the exclusive PCI owner to physically quiesce the radio.
        setProperty("SimpleATHNativePollTimerFailed", true);
        const IOReturn stopped = controller_->radioPower(false);
        if (stopped != kIOReturnSuccess)
        {
            setProperty("SimpleATHNativePollRadioStopError",
                        static_cast<uint32_t>(stopped), 32);
        }
        shutdown();
        return false;
    }
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
    dataRequested_ = false;
    dataRequestEpoch_ = 0;
    // A failed poll timer must not leave macOS showing an authenticated
    // link or an available AirPort radio after packet service has stopped.
    if (linked_)
    {
        linked_ = false;
        (void)setLinkState(static_cast<IO80211LinkState>(1), 0, false, 0, 0);
    }
    if (available_)
    {
        available_ = false;
        uint8_t availability[0xf8] {};
        put<uint32_t>(availability, 0, 1);
        put<uint32_t>(availability, 8, 0);
        emit(kDriverAvailableEvent, availability, sizeof(availability));
    }
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
    retireJoin(kIOReturnAborted, 3);
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
    return !stopping_ && controller_ != nullptr &&
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
    return !stopping_ && controller_ != nullptr &&
                   controller_->radioSnapshot(state) == kIOReturnSuccess &&
                   state.associated
               ? simpleath::tahoe::kApple80211StateRun
               : simpleath::tahoe::kApple80211StateInit;
}

IO80211LinkState SimpleATHInfraProtocol::linkState()
{
    simpleath::tahoe::WirelessSnapshot state {};
    const bool up = !stopping_ && controller_ != nullptr &&
                    controller_->radioSnapshot(state) == kIOReturnSuccess &&
                    state.radioAvailable && state.powered &&
                    !state.rfKillBlocked && state.associated &&
                    state.controlledPortOpen && state.associatedBeaconObserved;
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
        dataRequested_ = false;
        dataRequestEpoch_ = 0;
        packets_.disable();
        if (scanGeneration_ != 0)
        {
            (void)controller_->scanCancel(scanGeneration_);
            finishScan(true);
        }
        retireJoin(kIOReturnAborted, 3);
        return controller_->radioPower(false);
    }
    if (operation == kEnablePackets)
    {
        simpleath::tahoe::WirelessSnapshot state {};
        const IOReturn observed = controller_->radioSnapshot(state);
        if (observed != kIOReturnSuccess)
        {
            dataRequested_ = false;
            dataRequestEpoch_ = 0;
            packets_.disable();
            return observed;
        }
        if (!state.radioAvailable || !state.powered || state.rfKillBlocked ||
            state.epoch == 0 || !packets_.registered())
        {
            dataRequested_ = false;
            dataRequestEpoch_ = 0;
            packets_.disable();
            return kIOReturnNotReady;
        }
        // The OS may request its queues before association completes. Keep
        // that request, but do not start ordinary Ethernet packet transfer
        // until the corresponding association has opened the native port.
        dataRequested_ = true;
        dataRequestEpoch_ = state.epoch;
        if (!nativePacketAdmission(state, dataRequested_, dataRequestEpoch_))
        {
            packets_.disable();
            return kIOReturnSuccess;
        }
        const IOReturn enabled = packets_.enable();
        if (enabled != kIOReturnSuccess)
        {
            dataRequested_ = false;
            dataRequestEpoch_ = 0;
        }
        return enabled;
    }
    if (operation == kDisablePackets)
    {
        dataRequested_ = false;
        dataRequestEpoch_ = 0;
        packets_.disable();
        return kIOReturnSuccess;
    }
    // Leave/abort do not carry a payload in the modern WCL contract.
    if (operation == 0x1270 || operation == 0x12b8)
    {
        return leaveJoin(operation == 0x12b8);
    }
    if (data == nullptr)
    {
        return kIOReturnBadArgument;
    }
    // The native WCL getter slots use fixed old-SDK envelopes. These
    // immutable hardware/feature facts are valid before channel tuning and
    // even with the radio off; they never assert association or RF readiness.
    if (operation == kGetPowerSave)
    {
        static_assert(simpleath::tahoe::kApple80211Version == 1U &&
                          simpleath::tahoe::kApple80211PowerSaveDisabled == 0U,
                      "native status version and power-save value");
        static_assert(sizeof(simpleath::tahoe::NativeApple80211PowerSave) ==
                          sizeof(simpleath::tahoe::NativePowerSaveStatus),
                      "25G332 power-save data ABI");
        const auto status = simpleath::tahoe::ar9565PowerSaveStatus();
        memcpy(data, &status, sizeof(status));
        return kIOReturnSuccess;
    }
    if (operation == kGetNss)
    {
        static_assert(sizeof(simpleath::tahoe::NativeApple80211Nss) ==
                          sizeof(simpleath::tahoe::NativeNssStatus),
                      "25G332 NSS data ABI");
        const auto status = simpleath::tahoe::ar9565NssStatus();
        memcpy(data, &status, sizeof(status));
        return kIOReturnSuccess;
    }
    if (operation == 0x12d0)
    {
        return beginJoin(data);
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
        auto *out =
            static_cast<simpleath::tahoe::NativeApple80211Channel *>(data);
        *out = {};
        out->version = simpleath::tahoe::kApple80211Version;
        out->channel.version = simpleath::tahoe::kApple80211Version;
        out->channel.channel = state.channel;
        out->channel.flags = simpleath::tahoe::kApple80211Channel2Ghz |
                             simpleath::tahoe::kApple80211Channel20Mhz;
        return kIOReturnSuccess;
    }
    if (operation == 0xec8)
    {
        auto *out =
            static_cast<simpleath::tahoe::NativeApple80211StationMode *>(data);
        out->version = simpleath::tahoe::kApple80211Version;
        out->mode = simpleath::tahoe::kApple80211StationMode;
        return kIOReturnSuccess;
    }
    if (operation == 0xed0)
    {
        if (!state.associated || !state.signalMeasured)
        {
            return kIOReturnNotReady;
        }
        auto *out = static_cast<simpleath::tahoe::NativeApple80211Rssi *>(data);
        *out = {};
        out->version = simpleath::tahoe::kApple80211Version;
        out->numRadios = 1;
        out->unit = simpleath::tahoe::kApple80211RssiDbm;
        out->radio[0] = state.rssiDbm;
        out->aggregate = state.rssiDbm;
        return kIOReturnSuccess;
    }
    if (operation == 0x1060)
    {
        // The native WCL BSS envelope is 0x44 metadata plus 0x800 IE bytes.
        // Its owned snapshot must identify this very association generation.
        if (!state.associated || state.associationGeneration == 0 ||
            memcmp(state.bssid, state.associatedBss.bssid.bytes, 6) != 0 ||
            state.channel != state.associatedBss.channel)
        {
            return kIOReturnNotReady;
        }
        uint8_t message[simpleath::tahoe::kScanMessageBytes] {};
        const size_t length = simpleath::tahoe::encodeScanBss(
            state.associatedBss, message, sizeof(message));
        if (length == 0)
        {
            return kIOReturnNotReady;
        }
        memset(data, 0, 0x844);
        memcpy(data, message, length);
        return kIOReturnSuccess;
    }
    // Optional operations are explicitly rejected rather than acknowledging
    // unsupported offloads, VHT/HE, 5/6 GHz or unimplemented native requests.
    // Required association/PMK/AWDL operations remain tracked in the P0 TODO.
    setProperty("SimpleATHLastUnsupportedOperation", operation, 32);
    return kIOReturnUnsupported;
}

IOReturn SimpleATHInfraProtocol::beginJoin(void *data)
{
    using namespace simpleath::tahoe;
    if (join_.pending() || scanGeneration_ != 0)
    {
        return kIOReturnBusy;
    }
    JoinSelection selected {};
    if (!decodeJoin(static_cast<const uint8_t *>(data), kWclJoinRequestBytes,
                    selected))
    {
        clearJoin(selected);
        return kIOReturnBadArgument;
    }
    WirelessSnapshot state {};
    IOReturn result = controller_->radioSnapshot(state);
    if (result != kIOReturnSuccess || state.epoch == 0 || !state.powered ||
        !state.radioAvailable || state.rfKillBlocked || state.scanning)
    {
        clearJoin(selected);
        return result == kIOReturnSuccess ? kIOReturnNotReady : result;
    }
    if (state.joinRequestId > joinSerial_)
    {
        joinSerial_ = state.joinRequestId;
    }
    if (joinSerial_ == UINT64_MAX)
    {
        clearJoin(selected);
        return kIOReturnNoResources;
    }
    if (state.associated || join_.active())
    {
        result = leaveJoin(false);
        if (result != kIOReturnSuccess)
        {
            clearJoin(selected);
            return result;
        }
    }
    NativeConnectRequest request {};
    request.epoch = state.epoch;
    request.requestId = ++joinSerial_;
    memcpy(request.bssid, selected.bssid, sizeof(request.bssid));
    memcpy(request.ssid, selected.ssid, selected.ssidLength);
    request.ssidLength = selected.ssidLength;
    request.channel = selected.channel;
    request.wpa2Personal = selected.wpa2Personal;
    memcpy(request.pmk, selected.pmk, sizeof(request.pmk));
    // There is one driver-owned PMK copy while the provider's gate runs.
    clearJoin(selected);
    packets_.disable();
    result = controller_->stationJoin(request);
    if (result == kIOReturnSuccess)
    {
        if (!join_.begin(request.epoch, request.requestId, request.bssid,
                         request.wpa2Personal))
        {
            (void)controller_->stationLeave(3);
            result = kIOReturnInternalError;
        }
        else
        {
            clock_interval_to_deadline(kJoinTimeoutSeconds, kSecondScale,
                                       &joinDeadline_);
        }
    }
    clearConnectRequest(request);
    return result;
}

void SimpleATHInfraProtocol::emitJoin(unsigned int message, IOReturn status,
                                      uint16_t reason, bool up)
{
    uint8_t bytes[simpleath::tahoe::kWclConnectionEventBytes] {};
    const size_t length = simpleath::tahoe::encodeJoinEvent(
        message, join_.bssid(), {static_cast<int32_t>(status), reason}, up,
        bytes, sizeof(bytes));
    if (length != 0)
    {
        emit(message, bytes, length);
    }
}

void SimpleATHInfraProtocol::retireJoin(IOReturn status, uint16_t reason)
{
    using namespace simpleath::tahoe;
    // An old WCL packet-enable request must never reopen a later association
    // on the same physical PCI epoch after this join token is retired.
    dataRequested_ = false;
    dataRequestEpoch_ = 0;
    packets_.disable();
    const uint32_t notice = join_.lose();
    if ((notice & FailureNotice) != 0)
    {
        emitJoin(kWclConnectionEvent, status, reason, false);
    }
    if ((notice & DisconnectionNotice) != 0 || join_.beaconObserved())
    {
        emitJoin(kWclDeauthEvent, status, reason, false);
        emitJoin(kWclLinkEvent, status, reason, false);
    }
    join_.reset();
    joinDeadline_ = 0;
}

IOReturn SimpleATHInfraProtocol::leaveJoin(bool abort)
{
    // Revoke Skywalk demand before entering the physical owner's gate. A
    // failed or busy disassociation must not let the next poll reopen its
    // old controlled-port packets while WCL is trying to leave that AP.
    dataRequested_ = false;
    dataRequestEpoch_ = 0;
    packets_.disable();
    const IOReturn result = controller_->stationLeave(3);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    // An explicit WCL abort has its own completion, rather than announcing
    // a successful network connection or retaining an old request token.
    if (abort)
    {
        if (join_.beaconObserved())
        {
            emitJoin(simpleath::tahoe::kWclLinkEvent, kIOReturnAborted, 3,
                     false);
        }
        join_.reset();
        joinDeadline_ = 0;
        emit(simpleath::tahoe::kWclJoinAbortEvent, nullptr, 0);
    }
    else
    {
        retireJoin(kIOReturnAborted, 3);
    }
    return kIOReturnSuccess;
}

void SimpleATHInfraProtocol::pollJoin(
    const simpleath::tahoe::WirelessSnapshot &state, bool live)
{
    using namespace simpleath::tahoe;
    if (!join_.active())
    {
        return;
    }
    if (!live || !state.radioAvailable || !state.powered || state.rfKillBlocked)
    {
        retireJoin(kIOReturnOffline, 0);
        return;
    }
    uint64_t now = 0;
    clock_get_uptime(&now);
    if (join_.pending() && joinDeadline_ != 0 && now >= joinDeadline_)
    {
        (void)controller_->stationLeave(3);
        retireJoin(kIOReturnTimeout, 0);
        return;
    }
    JoinObservation progress {};
    progress.epoch = state.epoch;
    progress.requestId = state.joinRequestId;
    progress.associationGeneration = state.associationGeneration;
    memcpy(progress.bssid, state.bssid, sizeof(progress.bssid));
    progress.phase = state.joinPhase;
    progress.status = static_cast<int32_t>(state.joinStatus);
    progress.associated = state.associated;
    progress.controlledPortOpen = state.controlledPortOpen;
    progress.beaconObserved = state.associatedBeaconObserved;
    const uint32_t notices = join_.observe(progress);
    if ((notices & AssociationNotice) != 0)
    {
        emitJoin(kWclAssociationEvent, kIOReturnSuccess, 0, false);
    }
    if ((notices & BeaconNotice) != 0)
    {
        emitJoin(kWclLinkEvent, kIOReturnSuccess, 0, true);
        emitJoin(kWclFirstBeaconEvent, kIOReturnSuccess, 0, true);
    }
    if ((notices & SupplicantNotice) != 0)
    {
        emitJoin(kWclSupplicantEvent, kIOReturnSuccess, 0, true);
    }
    if ((notices & ConnectionNotice) != 0)
    {
        joinDeadline_ = 0;
        emitJoin(kWclConnectionEvent, kIOReturnSuccess, 0, true);
    }
    if ((notices & (FailureNotice | DisconnectionNotice)) != 0)
    {
        const IOReturn failure = state.joinStatus == kIOReturnSuccess
                                     ? kIOReturnOffline
                                     : state.joinStatus;
        // observe() already retired this token, but preserves its BSSID for
        // the last event. Never allow another association to satisfy it.
        if ((notices & FailureNotice) != 0)
        {
            emitJoin(kWclConnectionEvent, failure, 0, false);
        }
        if ((notices & DisconnectionNotice) != 0 || join_.beaconObserved())
        {
            emitJoin(kWclDeauthEvent, failure, 0, false);
            emitJoin(kWclLinkEvent, failure, 0, false);
        }
        dataRequested_ = false;
        dataRequestEpoch_ = 0;
        packets_.disable();
        join_.reset();
        joinDeadline_ = 0;
    }
}

IOReturn SimpleATHInfraProtocol::beginScan(void *data)
{
    if (scanGeneration_ != 0 || join_.pending())
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
    // A preliminary snapshot can belong to an earlier PCI epoch. Capture
    // the epoch and generation together at the transport's accepted start.
    uint64_t generation = 0;
    uint64_t epoch = 0;
    const auto result = controller_->scanStart(generation, epoch);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    scan_ = filter;
    pendingScanAckEpoch_ = 0;
    pendingScanAckGeneration_ = 0;
    scanEpoch_ = epoch;
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
    const uint64_t completedGeneration = scanGeneration_;
    const uint64_t completedEpoch = scanEpoch_;
    scanGeneration_ = 0;
    scanEpoch_ = 0;
    scan_ = {};
    emit(kScanDoneEvent, &status, sizeof(status));
    // This cross-gate call runs only after the OS event dispatch invocation.
    // Stale/retired epochs cannot acknowledge a successor's scan intent.
    const IOReturn acknowledged = controller_->acknowledgeScanCompletion(
        completedEpoch, completedGeneration);
    if (!stopping_ && acknowledged != kIOReturnSuccess)
    {
        // A provider completion can arrive late after an OS-local abort,
        // or its acknowledgement can fail after an ordinary SCAN_DONE.
        // Preserve either identity until its exact bridge intent is retired;
        // otherwise a new SCAN_REQ can remain blocked by EventPending.
        pendingScanAckEpoch_ = completedEpoch;
        pendingScanAckGeneration_ = completedGeneration;
    }
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
    if (pendingScanAckGeneration_ != 0U)
    {
        if ((live && state.epoch != pendingScanAckEpoch_) ||
            controller_->acknowledgeScanCompletion(pendingScanAckEpoch_,
                                                   pendingScanAckGeneration_) ==
                kIOReturnSuccess)
        {
            // A replaced provider retires the old pending acknowledgement;
            // an old generation cannot drain a successor's bridge intent.
            pendingScanAckEpoch_ = 0;
            pendingScanAckGeneration_ = 0;
        }
    }
    if (!live || state.epoch != lastEpoch_)
    {
        packets_.disable();
        if (scanGeneration_ != 0 && (!live || scanEpoch_ != state.epoch))
        {
            // A snapshot may be invalidated by an intervening mailbox
            // callback without a physical epoch loss. Request cancellation
            // before notifying WCL, then retain exact identity on failure.
            if (scanEpoch_ == lastEpoch_)
            {
                (void)controller_->scanCancel(scanGeneration_);
            }
            finishScan(true);
        }
        lastEpoch_ = live ? state.epoch : 0;
    }
    // Revocation is sticky across a physical epoch change, lost RF power or
    // an unreadable snapshot. A future link cannot replay an old OS request.
    if (!available || dataRequestEpoch_ != state.epoch)
    {
        dataRequested_ = false;
        dataRequestEpoch_ = 0;
    }
    if (available != available_)
    {
        available_ = available;
        uint8_t availability[0xf8] {};
        put<uint32_t>(availability, 0, 1);
        put<uint32_t>(availability, 8, available ? 1U : 0U);
        emit(kDriverAvailableEvent, availability, sizeof(availability));
    }
    pollJoin(state, live);
    // Only an accepted WCL join may announce a live AirPort link. A failed
    // join-status observation can retire the session while the physical
    // snapshot still describes the previous AP as associated/port-open.
    const bool link = available && join_.active() && !join_.pending() &&
                      state.associated && state.controlledPortOpen &&
                      state.associatedBeaconObserved;
    if (link != linked_)
    {
        linked_ = link;
        (void)setLinkState(static_cast<IO80211LinkState>(link ? 2 : 1), 0,
                           false, 0, 0);
    }
    // Retry a rejected mailbox handoff at most once per poll. Provider gate
    // callbacks only enqueue under the independent mailbox lock; no inverse
    // native work-loop callback is permitted.
    if (live && scanGeneration_ != 0U && scanEpoch_ == state.epoch &&
        !state.scanning)
    {
        (void)controller_->retryScanCompletion();
    }
    for (size_t i = 0;
         i < simpleath::tahoe::TahoeWirelessTransport::kEventCapacity; ++i)
    {
        simpleath::tahoe::WirelessEvent event {};
        uint64_t epoch = 0;
        uint64_t generation = 0;
        if (controller_->nextRadioEvent(event, epoch, generation) !=
            kIOReturnSuccess)
        {
            break;
        }
        if (event == simpleath::tahoe::WirelessEvent::ScanFinished &&
            simpleath::tahoe::acceptWirelessScanCompletion(
                epoch, generation, scanEpoch_, scanGeneration_, live,
                state.scanning))
        {
            // A late completion from an older same-epoch scan cannot
            // finish the new scan before its real radio dwell has ended.
            finishScan(false);
        }
    }
    if (live && nativePacketAdmission(state, dataRequested_, dataRequestEpoch_))
    {
        (void)packets_.enable();
    }
    else
    {
        packets_.disable();
    }
    packets_.poll();
    if (timer_->setTimeoutMS(kPollMilliseconds) != kIOReturnSuccess)
    {
        // A missed re-arm is terminal for the native WCL control-plane
        // lease: no subsequent callback can promise join timeout, scan-done
        // delivery, or port/association revocation. Request physical PCI
        // isolation before stopping local packet and interface service.
        setProperty("SimpleATHNativePollTimerFailed", true);
        const IOReturn stopped = controller_->radioPower(false);
        if (stopped != kIOReturnSuccess)
        {
            setProperty("SimpleATHNativePollRadioStopError",
                        static_cast<uint32_t>(stopped), 32);
        }
        shutdown();
    }
}
