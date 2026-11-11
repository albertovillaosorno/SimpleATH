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

#include "SimpleATHTahoeController.hpp"
#include "SimpleATHInfraProtocol.hpp"
#include "TahoeApple80211Values.hpp"
#include "TahoeCapabilities.hpp"
#include "diagnostics/NativeDiagnostics.hpp"
#include "platform/tahoe/NativeWirelessOwner.hpp"
#include "platform/tahoe/TahoeControllerABI.hpp"
#include "wifi/LegacyScanBridge.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/network/IOEthernetController.h>
#include <libkern/c++/OSMetaClass.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Modern IO80211 superclass declarations are local and ABI-scoped; the
// selected fixed request value layouts do not require private SDK headers.

// Preserve IOKit metaclass symbols and constructor semantics while ensuring
// its static registration cannot propagate exceptions during kext loading.
SimpleATHTahoeController::MetaClass SimpleATHTahoeController::gMetaClass;
const OSMetaClass *const SimpleATHTahoeController::metaClass =
    &SimpleATHTahoeController::gMetaClass;
constexpr const OSMetaClass *SimpleATHTahoeController::superClass;

SimpleATHTahoeController::SimpleATHTahoeController(const OSMetaClass *meta)
    : IO80211Controller(meta)
{
}

SimpleATHTahoeController::~SimpleATHTahoeController() = default;

const OSMetaClass *SimpleATHTahoeController::getMetaClass() const
{
    return &gMetaClass;
}

SimpleATHTahoeController::MetaClass::MetaClass() noexcept
    : OSMetaClass("SimpleATHTahoeController",
                  SimpleATHTahoeController::superClass,
                  sizeof(SimpleATHTahoeController))
{
}

OSDefineDefaultStructors(SimpleATHTahoeController, IO80211Controller)

    namespace
{
    constexpr char kDriverVersion[] = "SimpleATH native AR9565";
    constexpr char kHardwareVersion[] = "Qualcomm Atheros AR9565";

    IOReturn copyVersion(void *buffer, const char *string)
    {
        if ((buffer == nullptr) || (string == nullptr))
        {
            return kIOReturnBadArgument;
        }
        auto *out =
            static_cast<simpleath::tahoe::NativeApple80211Version *>(buffer);
        if (out->version != simpleath::tahoe::kApple80211Version)
        {
            return kIOReturnUnsupported;
        }
        const size_t size = strlen(string);
        if (size >= sizeof(out->string))
        {
            return kIOReturnNoSpace;
        }
        memset(&out->string[0], 0, sizeof(out->string));
        memcpy(&out->string[0], string, size);
        out->stringLength = static_cast<uint16_t>(size);
        return kIOReturnSuccess;
    }
}

// Emit milestone pairs around the native IO80211 initialization boundary.
// The physical owner has already reached DMA preparation on the Dell, but
// OpenCore logs end at ExitBootServices; the first missing "ready" marker
// helps isolate any synchronous native call that did not return during boot.
bool SimpleATHTahoeController::init(OSDictionary *properties)
{
    IOLog("SimpleATH Tahoe: IO80211InitEnter\n");
    if (!IO80211Controller::init(properties))
    {
        IOLog("SimpleATH Tahoe: IO80211InitFailed\n");
        return false;
    }
    IOLog("SimpleATH Tahoe: IO80211InitReady\n");
    return true;
}

bool SimpleATHTahoeController::start(IOService *provider)
{
    if (provider == nullptr)
    {
        return false;
    }
    IOLog("SimpleATH Tahoe: ControllerStartEnter\n");
    const auto diagnostics = simpleath::readNativeDiagnostics();
    simpleath::publishNativeDiagnostics(this, diagnostics);
    // Require an actual PCI epoch, radio owner and callback contract before
    // allowing the native superclass to publish any interface state.
    IOLog("SimpleATH Tahoe: ProviderBindEnter\n");
    if (transport_.bind(provider) != kIOReturnSuccess)
    {
        IOLog("SimpleATH Tahoe: ProviderBindFailed\n");
        setProperty("SimpleATHNativeFailureStage", "ProviderBind");
        return false;
    }
    // Native createWorkQueue/getWorkQueue base implementations are false/null
    // in 25G332. Supply the actual IO80211 queue before CoreCapture or WCL
    // starts: an ordinary IOWorkLoop is not a compatible replacement.
    IOLog("SimpleATH Tahoe: ProviderBindReady\n");
    IOLog("SimpleATH Tahoe: WorkQueueEnter\n");
    if (!createWorkQueue())
    {
        IOLog("SimpleATH Tahoe: WorkQueueFailed\n");
        setProperty("SimpleATHNativeFailureStage", "WorkQueue");
        transport_.unbind();
        return false;
    }
    IOLog("SimpleATH Tahoe: WorkQueueReady\n");
    IOLog("SimpleATH Tahoe: CoreCaptureEnter\n");
    if (!capture_.start(this, workQueue_))
    {
        IOLog("SimpleATH Tahoe: CoreCaptureFailed\n");
        setProperty("SimpleATHNativeFailureStage", "CoreCapture");
        transport_.unbind();
        capture_.stop();
        return false;
    }
    IOLog("SimpleATH Tahoe: CoreCaptureReady\n");
    IOLog("SimpleATH Tahoe: IO80211StartEnter\n");
    if (!IO80211Controller::start(provider))
    {
        IOLog("SimpleATH Tahoe: IO80211StartFailed\n");
        setProperty("SimpleATHNativeFailureStage", "IO80211Start");
        // The superclass may have constructed WCL event sources before a
        // later stage failed. Retire those while logging/queue remain valid.
        IO80211Controller::stop(provider);
        transport_.unbind();
        capture_.stop();
        return false;
    }
    IOLog("SimpleATH Tahoe: IO80211StartReady\n");
    started_ = true;
    IOLog("SimpleATH Tahoe: InfraInitEnter\n");
    infrastructure_ = new SimpleATHInfraProtocol;
    if (infrastructure_ == nullptr || !infrastructure_->initialize(this))
    {
        IOLog("SimpleATH Tahoe: InfraInitFailed\n");
        setProperty("SimpleATHNativeFailureStage", "InfraInit");
        stop(provider);
        return false;
    }
    IOLog("SimpleATH Tahoe: InfraInitReady\n");
    IOLog("SimpleATH Tahoe: InfraAttachEnter\n");
    if (!infrastructure_->attach(this))
    {
        IOLog("SimpleATH Tahoe: InfraAttachFailed\n");
        setProperty("SimpleATHNativeFailureStage", "InfraAttach");
        stop(provider);
        return false;
    }
    IOLog("SimpleATH Tahoe: InfraAttachReady\n");
    infrastructureAttached_ = true;
    IOLog("SimpleATH Tahoe: NativeAttachEnter\n");
    if (!attachInterface(infrastructure_, this))
    {
        IOLog("SimpleATH Tahoe: NativeAttachFailed\n");
        setProperty("SimpleATHNativeFailureStage", "NativeAttach");
        stop(provider);
        return false;
    }
    IOLog("SimpleATH Tahoe: NativeAttachReady\n");
    nativeAttached_ = true;
    IOLog("SimpleATH Tahoe: InfraStartEnter\n");
    if (!infrastructure_->start(this))
    {
        IOLog("SimpleATH Tahoe: InfraStartFailed\n");
        setProperty("SimpleATHNativeFailureStage", "InfraStart");
        stop(provider);
        return false;
    }
    IOLog("SimpleATH Tahoe: InfraStartReady\n");
    IOLog("SimpleATH Tahoe: InfraPublishEnter\n");
    infrastructure_->registerService();
    IOLog("SimpleATH Tahoe: InfraPublishReady\n");
    infrastructurePublished_ = true;
    removeProperty("SimpleATHNativeFailureStage");
    if (diagnostics.detailed)
    {
        IOLog("SimpleATH debug: native IO80211 queue, capture and fault "
              "reporter started\n");
    }
    return true;
}

void SimpleATHTahoeController::stop(IOService *provider)
{
    releaseInfrastructure();
    if (started_)
    {
        started_ = false;
        IO80211Controller::stop(provider);
    }
    transport_.unbind();
    capture_.stop();
}

void SimpleATHTahoeController::free()
{
    releaseInfrastructure();
    transport_.unbind();
    capture_.stop();
    if (workQueue_ != nullptr)
    {
        workQueue_->release();
        workQueue_ = nullptr;
    }
    IO80211Controller::free();
}

void SimpleATHTahoeController::releaseInfrastructure()
{
    if (infrastructure_ == nullptr)
    {
        return;
    }
    if (infrastructurePublished_)
    {
        infrastructurePublished_ = false;
        (void)infrastructure_->terminate(kIOServiceRequired |
                                         kIOServiceSynchronous);
    }
    infrastructure_->stop(this);
    if (nativeAttached_)
    {
        detachInterface(infrastructure_, false);
        nativeAttached_ = false;
    }
    if (infrastructureAttached_)
    {
        infrastructure_->detach(this);
        infrastructureAttached_ = false;
    }
    infrastructure_->release();
    infrastructure_ = nullptr;
}

IOReturn SimpleATHTahoeController::radioPower(bool on)
{
    return transport_.setPower(on);
}

IOReturn SimpleATHTahoeController::radioMac(const uint8_t address[6])
{
    return transport_.setMac(address);
}

bool SimpleATHTahoeController::createWorkQueue()
{
    if (workQueue_ == nullptr)
    {
        workQueue_ = IO80211WorkQueue::workQueue();
    }
    return workQueue_ != nullptr;
}

IO80211WorkQueue *SimpleATHTahoeController::getWorkQueue() const
{
    return workQueue_;
}

bool SimpleATHTahoeController::getLogPipes(CCPipe **logs, CCPipe **data,
                                           CCPipe **snapshots)
{
    return capture_.pipes(logs, data, snapshots);
}

bool SimpleATHTahoeController::isCommandProhibited(int command)
{
    // Tahoe passes an internal protocol command number, not necessarily a
    // legacy Apple80211 IOC. Permit normal dispatch only while a physical
    // radio owner is present; each concrete protocol operation still must
    // validate its request and report unsupported capability honestly.
    if (command < 0)
    {
        return true;
    }
    simpleath::tahoe::WirelessSnapshot state {};
    // Inventory and power-on requests must remain callable while the radio
    // is down. Concrete mutating callbacks enforce RF/power requirements.
    return transport_.snapshot(state) != kIOReturnSuccess;
}

IOReturn SimpleATHTahoeController::getHardwareAddress(IOEthernetAddress *out)
{
    if (out == nullptr)
    {
        return kIOReturnBadArgument;
    }
    simpleath::tahoe::WirelessSnapshot state {};
    const IOReturn result = transport_.snapshot(state);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    memcpy(&out->bytes[0], &state.currentMac[0], sizeof(out->bytes));
    return kIOReturnSuccess;
}

IOReturn
SimpleATHTahoeController::getDriverVersion(IO80211SkywalkInterface * /*unused*/,
                                           void *buffer)
{
    return copyVersion(buffer, &kDriverVersion[0]);
}

IOReturn SimpleATHTahoeController::getHardwareVersion(
    IO80211SkywalkInterface * /*unused*/, void *buffer)
{
    return copyVersion(buffer, &kHardwareVersion[0]);
}

IOReturn SimpleATHTahoeController::getCardCapabilities(
    IO80211SkywalkInterface * /*unused*/, void *buffer)
{
    if (buffer == nullptr)
    {
        return kIOReturnBadArgument;
    }
    // This is the modern fixed native GET envelope, not the smaller legacy
    // apple80211_capability_data in the compatibility SDK. Inventory must
    // remain available before RF/association and while the radio is off.
    const auto capabilities = simpleath::tahoe::ar9565Capabilities();
    memcpy(buffer, &capabilities, sizeof(capabilities));
    return kIOReturnSuccess;
}

IOReturn
SimpleATHTahoeController::getPOWER(IO80211SkywalkInterface * /*unused*/,
                                   void *buffer)
{
    if (buffer == nullptr)
    {
        return kIOReturnBadArgument;
    }
    auto *out = static_cast<simpleath::tahoe::NativeApple80211Power *>(buffer);
    if (out->version != simpleath::tahoe::kApple80211Version)
    {
        return kIOReturnUnsupported;
    }
    simpleath::tahoe::WirelessSnapshot state {};
    const IOReturn result = transport_.snapshot(state);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    out->numRadios = 1;
    for (auto &radio : out->powerState)
    {
        radio = simpleath::tahoe::kApple80211PowerOff;
    }
    out->powerState[0] =
        state.radioAvailable && state.powered && !state.rfKillBlocked
            ? simpleath::tahoe::kApple80211PowerOn
            : simpleath::tahoe::kApple80211PowerOff;
    return kIOReturnSuccess;
}

IOReturn
SimpleATHTahoeController::setPOWER(IO80211SkywalkInterface * /*unused*/,
                                   void *buffer)
{
    if (buffer == nullptr)
    {
        return kIOReturnBadArgument;
    }
    const auto *request =
        static_cast<const simpleath::tahoe::NativeApple80211Power *>(buffer);
    if (request->version != simpleath::tahoe::kApple80211Version ||
        request->numRadios != 1)
    {
        return kIOReturnUnsupported;
    }
    if (request->powerState[0] != simpleath::tahoe::kApple80211PowerOn &&
        request->powerState[0] != simpleath::tahoe::kApple80211PowerOff)
    {
        return kIOReturnUnsupported;
    }
    return transport_.setPower(request->powerState[0] ==
                               simpleath::tahoe::kApple80211PowerOn);
}

IOReturn
SimpleATHTahoeController::getCountryCode(IO80211SkywalkInterface * /*unused*/,
                                         void *buffer)
{
    if (buffer == nullptr)
    {
        return kIOReturnBadArgument;
    }
    auto *out =
        static_cast<simpleath::tahoe::NativeApple80211Country *>(buffer);
    if (out->version != simpleath::tahoe::kApple80211Version)
    {
        return kIOReturnUnsupported;
    }
    simpleath::tahoe::WirelessSnapshot state {};
    const IOReturn result = transport_.snapshot(state);
    if (result != kIOReturnSuccess)
    {
        return result;
    }
    if (state.country[0] == 0 || state.country[1] == 0)
    {
        return kIOReturnNotReady;
    }
    memset(&out->countryCode[0], 0, sizeof(out->countryCode));
    memcpy(&out->countryCode[0], &state.country[0],
           sizeof(state.country) < sizeof(out->countryCode)
               ? sizeof(state.country)
               : sizeof(out->countryCode));
    return kIOReturnSuccess;
}

IOReturn
SimpleATHTahoeController::setCountryCode(IO80211SkywalkInterface * /*unused*/,
                                         void *buffer)
{
    // Changing a registry country cannot authorize illegal RF channels or
    // raise power. Only a verified native regulatory policy may approve it.
    return (buffer != nullptr) ? kIOReturnUnsupported : kIOReturnBadArgument;
}

IOReturn
SimpleATHTahoeController::setGetDebugInfo(IO80211SkywalkInterface * /*unused*/,
                                          void *buffer)
{
    return (buffer != nullptr) ? kIOReturnUnsupported : kIOReturnBadArgument;
}

int32_t SimpleATHTahoeController::handleCardSpecific(
    IO80211SkywalkInterface * /*unused*/, unsigned long /*unused*/,
    void * /*unused*/, bool /*unused*/)
{
    return kIOReturnUnsupported;
}

CCLogStream *SimpleATHTahoeController::getLogger() const
{
    return capture_.logger();
}

CommonFaultReporter *SimpleATHTahoeController::getFaultReporterFromDriver()
{
    return capture_.faultReporter();
}

IOReturn
SimpleATHTahoeController::radioSnapshot(simpleath::tahoe::WirelessSnapshot &out)
{
    return transport_.snapshot(out);
}

IOReturn SimpleATHTahoeController::scanStart(uint64_t &generation)
{
    return transport_.startScan(generation);
}

IOReturn SimpleATHTahoeController::scanCancel(uint64_t generation)
{
    return transport_.cancelScan(generation);
}

IOReturn
SimpleATHTahoeController::scanNext(uint64_t generation,
                                   simpleath::ieee80211::NativeBssSnapshot &out)
{
    return transport_.nextBss(generation, out);
}

IOReturn SimpleATHTahoeController::stationJoin(
    const simpleath::tahoe::NativeConnectRequest &request)
{
    return transport_.connect(request);
}

IOReturn SimpleATHTahoeController::stationLeave(uint16_t reason)
{
    return transport_.disconnect(reason);
}

IOReturn
SimpleATHTahoeController::setCcmpKey(const simpleath::tahoe::NativeCcmpKey &key)
{
    return transport_.installKey(key);
}

IOReturn SimpleATHTahoeController::setControlledPort(bool enabled)
{
    return transport_.authorizePort(enabled);
}

IOReturn SimpleATHTahoeController::sendEthernet(const uint8_t *packet,
                                                size_t length)
{
    return transport_.transmitEthernet(packet, length);
}

IOReturn
SimpleATHTahoeController::nextRadioEvent(simpleath::tahoe::WirelessEvent &event,
                                         uint64_t &epoch)
{
    return transport_.takeEvent(event, epoch);
}

IOReturn SimpleATHTahoeController::receiveEthernet(uint8_t *packet,
                                                   size_t capacity,
                                                   size_t &length)
{
    return transport_.takeEthernet(packet, capacity, length);
}
