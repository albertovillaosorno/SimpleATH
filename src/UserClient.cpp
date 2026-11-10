//
//  UserClient.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/9/11.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "UserClient.hpp"
#include "Bridge.hpp"
#include "Patcher.hpp"
#include "WirelessABI.hpp"
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/OSMessageNotification.h>
#include <kern/task.h>
#include <libkern/OSTypes.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <mach/i386/vm_param.h>
#include <mach/mach_types.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace
{
    constexpr size_t kRoamBandEnableOffset = 12U;
    constexpr uint32_t kLegacyPointerBytes = 8U;
    constexpr uint32_t kPrivatePmkRequest = 0x178U;
    // Legacy requests which publish a returned payload after a set operation.
    constexpr uint32_t kSetRequestEcho0 = 0x5EU;
    constexpr uint32_t kSetRequestEcho1 = 0x125U;
    constexpr uint32_t kSetRequestEcho2 = 0x99U;
} // namespace

OSDefineMetaClassAndStructors(ATH80211UserClient, IOUserClient)

    bool ATH80211UserClient::entitled(const char *entitlement) const
{
    auto *value = copyClientEntitlement(ownerTask, entitlement);
    const bool allowed = value == kOSBooleanTrue;
    if (value != nullptr)
    {
        value->release();
    }
    return allowed;
}

IOReturn ATH80211UserClient::create(IOService *provider, task_t task,
                                    void *token, OSDictionary *properties,
                                    ath::InterfaceKind kind,
                                    IOUserClient **result)
{
    if ((result == nullptr) || (task == nullptr))
    {
        return kIOReturnBadArgument;
    }
    *result = nullptr;
    auto *client = new ATH80211UserClient;
    if (client == nullptr)
    {
        return kIOReturnNoMemory;
    }
    client->ownerTask = task;
    if (!client->initWithTask(task, token, 0, properties))
    {
        client->release();
        return kIOReturnError;
    }
    if (!client->entitled("com.apple.wlan.authentication"))
    {
        __atomic_fetch_add(&ath::counters.denied, 1ULL, __ATOMIC_RELAXED);
        client->release();
        return kIOReturnNotPrivileged;
    }
    if (!ath::Bridge::identify(provider, kind, client->endpoint))
    {
        client->release();
        return kIOReturnUnsupported;
    }
    client->endpoint.controller->retain();
    ath::Bridge::trackController(client->endpoint.controller);
    client->setProperty("IOUserClientDefaultLocking", kOSBooleanTrue);
    if (client->attach(provider))
    {
        if (client->start(provider))
        {
            __atomic_fetch_add(&ath::counters.opens, 1ULL, __ATOMIC_RELAXED);
            *result = client;
            return kIOReturnSuccess;
        }
        client->detach(provider);
    }
    client->release();
    return kIOReturnError;
}

bool ATH80211UserClient::start(IOService *provider)
{
    if (!IOUserClient::start(provider))
    {
        return false;
    }
    eventLock = IOLockAlloc();
    workLoop = endpoint.controller->getWorkLoop();
    if (workLoop != nullptr)
    {
        workLoop->retain();
    }
    commandGate = IOCommandGate::commandGate(this);
    filter.all = 1;
    if ((eventLock == nullptr) || (workLoop == nullptr) ||
        (commandGate == nullptr))
    {
        return false;
    }
    if (workLoop->addEventSource(commandGate) != kIOReturnSuccess)
    {
        return false;
    }
    gateAdded = true;
    registered = ath::Bridge::addClient(this);
    return registered;
}

void ATH80211UserClient::close()
{
    if (eventLock == nullptr)
    {
        return;
    }
    IOLockLock(eventLock);
    closed = true;
    monitoring = false;
    if (subscribed)
    {
        releaseAsyncReference64(asyncReference);
        memset(asyncReference, 0, sizeof(asyncReference));
        subscribed = false;
    }
    IOLockUnlock(eventLock);
    if (registered)
    {
        registered = false;
        ath::Bridge::removeClient(this);
    }
}

IOReturn ATH80211UserClient::closeAction(OSObject *owner, void *, void *,
                                         void *, void *)
{
    static_cast<ATH80211UserClient *>(owner)->close();
    return kIOReturnSuccess;
}

IOReturn ATH80211UserClient::clientClose()
{
    if ((commandGate != nullptr) && gateAdded)
    {
        commandGate->runAction(closeAction);
    }
    else
    {
        close();
    }
    if (!isInactive())
    {
        terminate();
    }
    return kIOReturnSuccess;
}

IOReturn ATH80211UserClient::clientDied()
{
    return clientClose();
}

void ATH80211UserClient::stop(IOService *provider)
{
    if ((commandGate != nullptr) && gateAdded)
    {
        commandGate->runAction(closeAction);
        workLoop->removeEventSource(commandGate);
        gateAdded = false;
    }
    else
    {
        close();
    }
    IOUserClient::stop(provider);
}

void ATH80211UserClient::free()
{
    close();
    if (commandGate != nullptr)
    {
        if (gateAdded && (workLoop != nullptr))
        {
            workLoop->removeEventSource(commandGate);
        }
        commandGate->release();
    }
    if (workLoop != nullptr)
    {
        workLoop->release();
    }
    if (ringMemory != nullptr)
    {
        ringMemory->release();
    }
    if (stateMemory != nullptr)
    {
        stateMemory->release();
    }
    if (eventLock != nullptr)
    {
        IOLockFree(eventLock);
    }
    if (endpoint.controller != nullptr)
    {
        endpoint.controller->release();
    }
    IOUserClient::free();
}

IOReturn ATH80211UserClient::externalMethod(
    uint32_t selector, IOExternalMethodArguments *arguments,
    IOExternalMethodDispatch *, OSObject *, void *)
{
    if ((arguments == nullptr) || (commandGate == nullptr) || !gateAdded ||
        selector >= ath::Bridge::abi().selectorCount)
    {
        return kIOReturnBadArgument;
    }
    __atomic_fetch_add(&ath::counters.selectors[selector], 1ULL,
                       __ATOMIC_RELAXED);
    return commandGate->runAction(
        dispatchAction,
        reinterpret_cast<void *>(static_cast<uintptr_t>(selector)), arguments);
}

IOReturn ATH80211UserClient::dispatchAction(OSObject *owner, void *selector,
                                            void *arguments, void *, void *)
{
    return static_cast<ATH80211UserClient *>(owner)->dispatch(
        static_cast<uint32_t>(reinterpret_cast<uintptr_t>(selector)),
        static_cast<IOExternalMethodArguments *>(arguments));
}

IOReturn ATH80211UserClient::dispatch(uint32_t selector,
                                      IOExternalMethodArguments *arguments)
{
    if (closed || isInactive() || !ath::Bridge::ready())
    {
        return kIOReturnNotOpen;
    }
    const auto method = static_cast<ath::Selector>(selector);
    if ((arguments->scalarOutputCount != 0U) ||
        arguments->scalarInputCount !=
            (method == ath::Selector::MapUserBuffer ? 2U : 0U))
    {
        return kIOReturnBadArgument;
    }
    if (method == ath::Selector::Command ||
        method == ath::Selector::LargeCommand)
    {
        if (arguments->asyncReferenceCount != 0U)
        {
            return kIOReturnBadArgument;
        }
        return runCommand(arguments, method == ath::Selector::Command
                                         ? ath::commandCapacity
                                         : ath::largeCommandCapacity);
    }
    if ((arguments->structureInputSize != 0U) ||
        (arguments->structureInputDescriptor != nullptr))
    {
        return kIOReturnBadArgument;
    }
    if (method != ath::Selector::Subscribe &&
        (arguments->asyncReferenceCount != 0U))
    {
        return kIOReturnBadArgument;
    }
    switch (method)
    {
        case ath::Selector::UseIOUC:
        case ath::Selector::UseEventPipe:
        case ath::Selector::DriverKitSupported:
            {
                if ((arguments->structureOutput == nullptr) ||
                    arguments->structureOutputSize != 1 ||
                    (arguments->structureOutputDescriptor != nullptr))
                {
                    return kIOReturnBadArgument;
                }
                auto *value =
                    static_cast<uint8_t *>(arguments->structureOutput);
                *value = static_cast<uint8_t>(
                    method != ath::Selector::DriverKitSupported);
                return kIOReturnSuccess;
            }
        case ath::Selector::Subscribe:
        case ath::Selector::MonitorStart:
        case ath::Selector::MonitorStop:
        case ath::Selector::MapUserBuffer:
            if ((arguments->structureOutputSize != 0U) ||
                (arguments->structureOutputDescriptor != nullptr))
            {
                return kIOReturnBadArgument;
            }
            break;
        default:
            return kIOReturnUnsupported;
    }
    switch (method)
    {
        case ath::Selector::Subscribe:
            return subscribe(arguments);
        case ath::Selector::MonitorStart:
            return startMonitor();
        case ath::Selector::MonitorStop:
            IOLockLock(eventLock);
            monitoring = false;
            IOLockUnlock(eventLock);
            return kIOReturnSuccess;
        default:
            return kIOReturnUnsupported;
    }
}

static IOReturn runRoamProfiles(const ath::Endpoint &endpoint, bool set,
                                ath::LegacyRequest &request, uint8_t *shadow,
                                size_t capacity)
{
    uint8_t profiles[ath::nativeRoamProfileSize] {};
    if (set)
    {
        memcpy(profiles, shadow, sizeof(profiles));
    }
    IOReturn result = kIOReturnBadArgument;
    for (size_t index = 0; index < 2; ++index)
    {
        auto *band = profiles + (index * ath::nativeRoamBandSize);
        if (set)
        {
            if (ath::readUInt32(band + kRoamBandEnableOffset) == 0U)
            {
                continue;
            }
            if (!ath::prepareRoamBand(request.request, shadow, capacity, band,
                                      ath::nativeRoamBandSize))
            {
                return kIOReturnBadArgument;
            }
        }
        else
        {
            memset(shadow, 0, ath::legacyRoamBandSize);
            shadow[0] = 1;
            shadow[4] = static_cast<uint8_t>(2U << index);
            request.request.length = ath::legacyRoamBandSize;
        }
        result = static_cast<IOReturn>(
            ath::Bridge::command(endpoint, set, request, shadow, capacity));
        if (result != kIOReturnSuccess)
        {
            return result;
        }
        if (!set && !ath::expandRoamBand(request.request, shadow, capacity,
                                         band, ath::nativeRoamBandSize))
        {
            return kIOReturnOverrun;
        }
    }
    if (!set && result == kIOReturnSuccess)
    {
        memcpy(shadow, profiles, sizeof(profiles));
        request.request.length = sizeof(profiles);
    }
    return result;
}

IOReturn ATH80211UserClient::runCommand(IOExternalMethodArguments *arguments,
                                        size_t capacity)
{
    const auto packetSize =
        sizeof(ath::CommandHeader) + capacity + sizeof(ath::Request);
    const size_t inputSize =
        (arguments->structureInputDescriptor != nullptr)
            ? arguments->structureInputDescriptor->getLength()
            : arguments->structureInputSize;
    const size_t outputSize = (arguments->structureOutputDescriptor != nullptr)
                                  ? arguments->structureOutputDescriptorSize
                                  : arguments->structureOutputSize;
    if (inputSize != packetSize || outputSize > capacity ||
        ((arguments->structureInputDescriptor != nullptr) &&
         (arguments->structureInputSize != 0U)) ||
        ((arguments->structureOutputDescriptor != nullptr) &&
         ((arguments->structureOutputSize != 0U) ||
          outputSize > arguments->structureOutputDescriptor->getLength())) ||
        ((arguments->structureInputDescriptor == nullptr) &&
         (arguments->structureInput == nullptr)) ||
        ((arguments->structureOutputDescriptor == nullptr) &&
         (outputSize != 0U) && (arguments->structureOutput == nullptr)))
    {
        return kIOReturnBadArgument;
    }
    auto *packet = static_cast<uint8_t *>(IOMalloc(packetSize));
    if (packet == nullptr)
    {
        return kIOReturnNoMemory;
    }
    IOReturn result = kIOReturnBadArgument;
    if (arguments->structureInputDescriptor != nullptr)
    {
        auto status =
            arguments->structureInputDescriptor->prepare(kIODirectionOut);
        if (status != kIOReturnSuccess)
        {
            IOFree(packet, packetSize);
            return status;
        }
        const auto copied = arguments->structureInputDescriptor->readBytes(
            0, packet, packetSize);
        status = arguments->structureInputDescriptor->complete(kIODirectionOut);
        if (copied != packetSize || status != kIOReturnSuccess)
        {
            memset(packet, 0, packetSize);
            IOFree(packet, packetSize);
            return copied != packetSize ? kIOReturnVMError : status;
        }
    }
    else
    {
        memcpy(packet, arguments->structureInput, packetSize);
    }
    auto *header = reinterpret_cast<ath::CommandHeader *>(packet);
    auto *shadow = packet + sizeof(*header);
    ath::LegacyRequest legacy {};
    memcpy(&legacy.request, shadow + capacity, sizeof(legacy.request));
    legacy.pointerSize = kLegacyPointerBytes;
    const auto request = legacy.request.type;
    const bool set = header->command == ath::setCommand;
    const bool get = header->command == ath::getCommand;
    const auto &abi = ath::Bridge::abi();
    const bool scalar =
        get && ath::Bridge::isScalarGet(static_cast<uint32_t>(request));
    const bool scanResult = get && request == ath::scanResultRequest &&
                            outputSize == abi.scanResultSize;
    const bool capabilities = get && request == ath::cardCapabilitiesRequest &&
                              outputSize == abi.capabilitySize;
    const bool associate = set && request == ath::associateRequest;
    const bool roamProfiles = request == ath::roamProfileRequest &&
                              abi.roamProfileSize == ath::nativeRoamProfileSize;
    bool outputPrepared = false;
    __atomic_fetch_add(&ath::counters.commands, 1ULL, __ATOMIC_RELAXED);
    __atomic_store_n(&ath::counters.lastRequest, static_cast<uint32_t>(request),
                     __ATOMIC_RELAXED);
    if (associate)
    {
        __atomic_fetch_add(&ath::counters.associationRequests, 1ULL,
                           __ATOMIC_RELAXED);
    }
    if ((!set && !get) || header->length > capacity ||
        (strncmp(legacy.request.interfaceName, endpoint.name,
                 sizeof(endpoint.name)) != 0))
    {
        goto done;
    }
    if ((get && request == ath::scanResultRequest && !scanResult) ||
        (get && request == ath::cardCapabilitiesRequest && !capabilities) ||
        (associate && header->length != abi.associateSize) ||
        (set && request == ath::scanMultipleRequest &&
         header->length != abi.scanMultipleSize) ||
        (request == ath::roamProfileRequest &&
         (get ? outputSize : header->length) != abi.roamProfileSize))
    {
        goto done;
    }
    if (get && request == kPrivatePmkRequest &&
        !entitled("com.apple.private.wifi.IO80211.get_pmk"))
    {
        result = kIOReturnNotPrivileged;
        goto done;
    }
    if (scalar && outputSize < sizeof(legacy.request.value))
    {
        result = kIOReturnNoSpace;
        goto done;
    }
    if ((arguments->structureOutputDescriptor != nullptr) && (outputSize != 0U))
    {
        const auto status =
            arguments->structureOutputDescriptor->prepare(kIODirectionIn);
        if (status != kIOReturnSuccess)
        {
            result = status;
            goto done;
        }
        outputPrepared = true;
    }
    legacy.request.data = reinterpret_cast<uintptr_t>(shadow);
    legacy.request.length =
        static_cast<uint32_t>(get ? outputSize : header->length);
    if (scanResult &&
        !ath::prepareScanResult(legacy.request, shadow, capacity, abi))
    {
        goto done;
    }
    if (set && request == ath::scanMultipleRequest &&
        !ath::prepareScanMultiple(legacy.request, shadow, capacity, abi))
    {
        goto done;
    }
    if (associate &&
        !ath::prepareAssociate(legacy.request, shadow, capacity, abi))
    {
        goto done;
    }
    if (set && (abi.filterMonitorEvents != 0U) &&
        static_cast<uint32_t>(request) == abi.filterMonitorEvents)
    {
        if (legacy.request.length != sizeof(ath::EventFilter) ||
            header->length < sizeof(ath::EventFilter))
        {
            goto done;
        }
        IOLockLock(eventLock);
        memcpy(&filter, shadow, sizeof(filter));
        IOLockUnlock(eventLock);
        result = kIOReturnSuccess;
    }
    else if (roamProfiles)
    {
        result = runRoamProfiles(endpoint, set, legacy, shadow, capacity);
    }
    else
    {
        result = static_cast<IOReturn>(
            ath::Bridge::command(endpoint, set, legacy, shadow, capacity));
    }
    if (result == kIOReturnSuccess)
    {
        if (capabilities && !ath::expandCapabilities(
                                legacy.request, shadow, capacity, abi,
                                endpoint.kind == ath::InterfaceKind::Classic))
        {
            result = kIOReturnOverrun;
            goto done;
        }
        if (scanResult)
        {
            if (!ath::expandScanResult(legacy.request, shadow, capacity, abi))
            {
                result = kIOReturnOverrun;
                goto done;
            }
        }
        if (scalar &&
            !ath::encodeScalarResult(legacy.request, shadow, capacity))
        {
            result = kIOReturnNoSpace;
            goto done;
        }
        size_t produced = get ? legacy.request.length : 0;
        if (set && (request == kSetRequestEcho0 ||
                    request == kSetRequestEcho1 || request == kSetRequestEcho2))
        {
            produced = legacy.request.length;
        }
        if (produced > capacity)
        {
            result = kIOReturnOverrun;
            goto done;
        }
        if (produced > outputSize)
        {
            result = kIOReturnNoSpace;
            goto done;
        }
        if (arguments->structureOutputDescriptor != nullptr)
        {
            if (arguments->structureOutputDescriptor->writeBytes(
                    0, shadow, produced) != produced)
            {
                result = kIOReturnVMError;
                goto done;
            }
            arguments->structureOutputDescriptorSize =
                static_cast<uint32_t>(produced);
        }
        else
        {
            if (produced != 0U)
            {
                memcpy(arguments->structureOutput, shadow, produced);
            }
            arguments->structureOutputSize = static_cast<uint32_t>(produced);
        }
    }
done:
    if (outputPrepared)
    {
        const auto status =
            arguments->structureOutputDescriptor->complete(kIODirectionIn);
        if (result == kIOReturnSuccess)
        {
            result = status;
        }
    }
    if (scanResult && result == kIOReturnSuccess)
    {
        __atomic_fetch_add(&ath::counters.scanRecords, 1ULL, __ATOMIC_RELAXED);
    }
    if (associate)
    {
        __atomic_store_n(&ath::counters.lastAssociationResult,
                         static_cast<uint32_t>(result), __ATOMIC_RELAXED);
        if (result == kIOReturnSuccess)
        {
            __atomic_fetch_add(&ath::counters.associationAccepted, 1ULL,
                               __ATOMIC_RELAXED);
        }
    }
    if (result != kIOReturnSuccess)
    {
        __atomic_fetch_add(&ath::counters.errors, 1ULL, __ATOMIC_RELAXED);
        DBGLOG(
            "iouc",
            "%s command 0x%08x request %d length %u output %lu result 0x%08x",
            endpoint.name, header->command, request, header->length,
            static_cast<unsigned long>(outputSize), result);
    }
    __atomic_store_n(&ath::counters.lastResult, static_cast<uint32_t>(result),
                     __ATOMIC_RELAXED);
    memset(packet, 0, packetSize);
    IOFree(packet, packetSize);
    return result;
}

IOReturn ATH80211UserClient::startMonitor()
{
    ath::Bridge::refreshAvailability(endpoint);
    IOLockLock(eventLock);
    if (ringMemory == nullptr)
    {
        ringMemory = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task,
            static_cast<IOOptionBits>(kIOMemoryKernelUserShared) |
                static_cast<IOOptionBits>(kIODirectionInOut),
            ath::eventCapacity, PAGE_SIZE);
    }
    if (stateMemory == nullptr)
    {
        stateMemory = IOBufferMemoryDescriptor::inTaskWithOptions(
            kernel_task,
            static_cast<IOOptionBits>(kIOMemoryKernelUserShared) |
                static_cast<IOOptionBits>(kIODirectionInOut),
            PAGE_SIZE, PAGE_SIZE);
    }
    if ((ringMemory == nullptr) || (stateMemory == nullptr))
    {
        IOLockUnlock(eventLock);
        return kIOReturnNoMemory;
    }
    if (!monitoring)
    {
        memset(ringMemory->getBytesNoCopy(), 0, ringMemory->getLength());
        memset(stateMemory->getBytesNoCopy(), 0, stateMemory->getLength());
        writeOffset = 0;
        ath::AvailabilityEvent initial {};
        monitorSerial = ath::Bridge::copyAvailability(endpoint, initial);
        monitoring = true;
        if ((initial.length != 0U) && filter.accepts(ath::driverAvailableEvent))
        {
            const auto result = ath::EventRing::append(
                static_cast<uint8_t *>(ringMemory->getBytesNoCopy()),
                ath::eventCapacity,
                static_cast<ath::EventState *>(stateMemory->getBytesNoCopy()),
                writeOffset, sequence, endpoint.name, ath::driverAvailableEvent,
                initial.payload, initial.length, initial.seconds,
                initial.microseconds);
            if (result == ath::RingResult::Written)
            {
                __atomic_fetch_add(&ath::counters.availabilityReplays, 1ULL,
                                   __ATOMIC_RELAXED);
                if (subscribed)
                {
                    notifyAvailable();
                }
            }
        }
    }
    IOLockUnlock(eventLock);
    return kIOReturnSuccess;
}

IOReturn ATH80211UserClient::subscribe(IOExternalMethodArguments *arguments)
{
    if ((arguments->asyncWakePort == nullptr) ||
        (arguments->asyncReference == nullptr) ||
        arguments->asyncReferenceCount != kOSAsyncRef64Count)
    {
        return kIOReturnBadArgument;
    }
    IOLockLock(eventLock);
    if (subscribed)
    {
        releaseAsyncReference64(asyncReference);
    }
    memcpy(asyncReference, arguments->asyncReference, sizeof(asyncReference));
    subscribed = true;
    if (monitoring && __atomic_load_n(&static_cast<ath::EventState *>(
                                           stateMemory->getBytesNoCopy())
                                           ->read,
                                      __ATOMIC_ACQUIRE) != writeOffset)
    {
        notifyAvailable();
    }
    IOLockUnlock(eventLock);
    return kIOReturnSuccess;
}

IOReturn ATH80211UserClient::clientMemoryForType(UInt32 type,
                                                 IOOptionBits *options,
                                                 IOMemoryDescriptor **memory)
{
    if ((options == nullptr) || (memory == nullptr) || (eventLock == nullptr))
    {
        return kIOReturnBadArgument;
    }
    *memory = nullptr;
    IOLockLock(eventLock);
    auto *descriptor = type == 1   ? ringMemory
                       : type == 2 ? stateMemory
                                   : nullptr;
    IOReturn status = kIOReturnBadArgument;
    if (!closed && (descriptor != nullptr))
    {
        *options = type == 1 ? kIOMapReadOnly : 0;
        descriptor->retain();
        *memory = descriptor;
        status = kIOReturnSuccess;
    }
    IOLockUnlock(eventLock);
    return status;
}

void ATH80211UserClient::receive(IOService *controller, const char *name,
                                 uint32_t event, const void *payload,
                                 size_t length, uint64_t seconds,
                                 uint64_t microseconds, uint64_t serial)
{
    if (endpoint.controller != controller ||
        (strncmp(name, endpoint.name, sizeof(endpoint.name)) != 0))
    {
        return;
    }
    IOLockLock(eventLock);
    if (closed || !monitoring || serial <= monitorSerial ||
        !filter.accepts(event))
    {
        IOLockUnlock(eventLock);
        return;
    }
    const auto result = ath::EventRing::append(
        static_cast<uint8_t *>(ringMemory->getBytesNoCopy()),
        ath::eventCapacity,
        static_cast<ath::EventState *>(stateMemory->getBytesNoCopy()),
        writeOffset, sequence, name, event, payload, length, seconds,
        microseconds);
    if (result != ath::RingResult::Written)
    {
        __atomic_fetch_add(&ath::counters.dropped, 1ULL, __ATOMIC_RELAXED);
    }
    if (event == ath::scanDoneEvent && result == ath::RingResult::Written)
    {
        __atomic_fetch_add(&ath::counters.scanDoneRecords, 1ULL,
                           __ATOMIC_RELAXED);
    }
    if (subscribed && result != ath::RingResult::Invalid)
    {
        notifyAvailable();
    }
    IOLockUnlock(eventLock);
}

void ATH80211UserClient::notifyAvailable()
{
    const auto status = sendAsyncResult64WithOptions(
        asyncReference, ath::eventNotification, nullptr, 0,
        static_cast<IOReturn>(kIOUserNotifyOptionCanDrop));
    auto *counter = status == kIOReturnSuccess
                        ? &ath::counters.notifications
                        : &ath::counters.notificationErrors;
    __atomic_fetch_add(counter, 1ULL, __ATOMIC_RELAXED);
}
