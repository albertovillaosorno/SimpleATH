//
//  Bridge.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/9/4.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Bridge.hpp"
#include "HardwareIdentity.hpp"
#include "NativeSkywalk.hpp"
#include "NativeUserClient.hpp"
#include "Patcher.hpp"
#include "Payload.hpp"
#include "Profiles.hpp"
#include "UserClient.hpp"
#include "WirelessABI.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <cstdint>
#include <i386/types.h>
#include <kern/clock.h>
#include <kern/thread.h>
#include <kern/thread_call.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSObject.h>
#include <libkern/copyio.h>
#include <libkern/libkern.h>
#include <mach-o/loader.h>
#include <mach/i386/vm_types.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/systm.h>

namespace ath
{
    // Values below are serialized/native selector, instruction and width
    // contracts; naming them does not change the wire or binary layout.
    constexpr uint32_t kDisabledStateBit = 0x80000000U;
    constexpr uint32_t kReadyStateBits = 7;
    constexpr uint32_t kBroadcomPciVendor = 0x14E4U;
    constexpr uint32_t kAppleBoardVendor = 0x106BU;
    constexpr uint32_t kCountryQuerySelector = 0xC03069C9U;
    constexpr int kCountryQueryType = 28;
    constexpr size_t kHardwareTextOffset = 6;
    constexpr size_t kHardwareTextCapacity = 256;
    constexpr size_t kAssociationAddressBytes = 6;
    constexpr uint32_t kAssociationStatusSelector = 50;
    constexpr uint32_t kAssociationResultSelector = 21;
    constexpr uint32_t kAssociationAddressSelector = 9;
    constexpr uint32_t kPowerAvailabilitySelector = 19;
    constexpr size_t kPowerSnapshotWordOffset = 8;
    constexpr uint32_t kMaximumMachLoadCommands = 512;
    constexpr uint8_t kJmpRel32Opcode = 0xE9;
    constexpr uint8_t kJmpIndirectOpcode = 0xFF;
    constexpr uint8_t kJmpRipRelativeMode = 0x25;
    constexpr uint8_t kCallRel32Opcode = 0xE8;
    constexpr size_t kRipRelativeBranchTargetOffset = 6;
    constexpr uint32_t kRel32CallLength = 5;
    constexpr uint32_t kCopySiteCapacity = 14;
    constexpr uint32_t kNumberBits32 = 32;
    constexpr uint32_t kNumberBits64 = 64;
    constexpr size_t kMetricNameCapacity = 24;

    // Decode native kernel addresses without aliasing a function or object
    // pointer as an integer. The target is x86_64 with equal address widths.
    template <typename Pointer>
    static Pointer pointerFromAddress(uintptr_t address)
    {
        static_assert(
            sizeof(Pointer) == sizeof(address),
            "kernel address and native function pointer widths differ");
        Pointer symbol = nullptr;
        __builtin_memcpy(static_cast<void *>(&symbol),
                         static_cast<const void *>(&address), sizeof(Pointer));
        return symbol;
    }

    template <typename Pointer> static uintptr_t pointerAddress(Pointer pointer)
    {
        static_assert(sizeof(Pointer) == sizeof(uintptr_t),
                      "kernel pointer and address widths differ");
        uintptr_t address = 0U;
        __builtin_memcpy(static_cast<void *>(&address),
                         static_cast<const void *>(&pointer), sizeof(address));
        return address;
    }

    Counters counters {};
    static uint32_t state;
    static IOService *observedController;
    static const char *failure = "WaitingForDependencies";
    static IOSimpleLock *contextLock;
    static IOSimpleLock *hubLock;
    static constexpr size_t kClientCapacity = 64;
    static ATH80211UserClient *clients[kClientCapacity];
    static thread_call_t eventCall;

    namespace
    {
        struct CopyContext
        {
                thread_t thread;
                uintptr_t begin;
                size_t length;
                CopyContext *next;
        };

        struct PendingEvent
        {
                IOService *controller;
                IOService *interface;
                uint64_t serial;
                char name[kInterfaceNameCapacity];
                uint32_t event;
                uint32_t length;
                uint64_t seconds;
                uint64_t microseconds;
                uint8_t payload[maximumEventPayload];
        };
    } // namespace

    static CopyContext *contexts;
    static PendingEvent *pending;
    static uint32_t pendingRead;
    static uint32_t pendingWrite;
    static uint64_t serial;
    static constexpr uint32_t kPendingCapacity = 64;
    static constexpr size_t kAvailabilityCapacity = 16;

    static struct
    {
            IOService *controller;
            char name[kInterfaceNameCapacity];
            bool original;
            AvailabilityEvent event;
    } availability[kAvailabilityCapacity];

    using NewClient = IOReturn (*)(IOService *, task_t, void *, uint32_t,
                                   OSDictionary *, IOUserClient **);
    using PostMessage = IOReturn (*)(IOService *, uint32_t, void *, size_t);
    using Ioctl = int (*)(IOService *, IOService *, IOService *, IOService *,
                          void *);
    using Controller = IOService *(*)(IOService *);
    using BSDName = const char *(*)(IOService *);
    using PerformCommand = int (*)(IOService *, IOService *, unsigned long,
                                   void *, void *);

    static NewClient originalClassicClient;
    static NewClient originalVirtualClient;
    static NewClient originalSkywalkClient;
    static PostMessage originalClassicEvent;
    static PostMessage originalVirtualEvent;
    static PostMessage originalInfraEvent;
    static Ioctl getRequest;
    static Ioctl setRequest;
    static Controller classicController;
    static Controller virtualController;
    static BSDName classicName;
    static BSDName virtualName;
    static BSDName skywalkName;
    static PerformCommand classicCommand;
    static const UserABI *activeABI;

    static void reject(const char *reason)
    {
        __atomic_store_n(&failure, reason, __ATOMIC_RELEASE);
        __atomic_fetch_or(&state, kDisabledStateBit, __ATOMIC_RELEASE);
        SYSLOG("bridge", "disabled: %s", reason);
    }

    bool Bridge::ready()
    {
        return __atomic_load_n(&state, __ATOMIC_ACQUIRE) == kReadyStateBits;
    }

    const UserABI &Bridge::abi()
    {
        return *activeABI;
    }

    bool Bridge::isScalarGet(uint32_t request)
    {
        for (auto const entry : kScalarGetRequests)
        {
            if (entry == request)
            {
                return true;
            }
        }
        return false;
    }

    static bool contains(uintptr_t begin, size_t size, uintptr_t address,
                         size_t length)
    {
        return address >= begin && address - begin <= size &&
               length <= size - (address - begin);
    }

    static bool isShadow(uintptr_t address, size_t size)
    {
        bool found = false;
        auto const *thread = current_thread();
        IOSimpleLockLock(contextLock);
        for (auto const *context = contexts; context != nullptr;
             context = context->next)
        {
            if (context->thread == thread &&
                contains(context->begin, context->length, address, size))
            {
                found = true;
                break;
            }
        }
        IOSimpleLockUnlock(contextLock);
        return found;
    }

    static int bridgeCopyIn(user_addr_t address, void *destination, size_t size)
    {
        if (!isShadow(static_cast<uintptr_t>(address), size))
        {
            return copyin(address, destination, size);
        }
        memcpy(destination, pointerFromAddress<const void *>(address), size);
        return 0;
    }

    static int bridgeCopyOut(const void *source, user_addr_t address,
                             size_t size)
    {
        if (!isShadow(static_cast<uintptr_t>(address), size))
        {
            return copyout(source, address, size);
        }
        memcpy(pointerFromAddress<void *>(address), source, size);
        return 0;
    }

    bool Bridge::identify(IOService *interface, InterfaceKind kind,
                          Endpoint &endpoint)
    {
        if ((interface == nullptr) || !ready())
        {
            return false;
        }
        IOService *controller = nullptr;
        const char *name = nullptr;
        switch (kind)
        {
            case InterfaceKind::Classic:
                controller = classicController(interface);
                name = classicName(interface);
                break;
            case InterfaceKind::Virtual:
                controller = virtualController(interface);
                name = virtualName(interface);
                break;
            case InterfaceKind::Skywalk:
                for (IOService *parent = interface->getProvider();
                     parent != nullptr; parent = parent->getProvider())
                {
                    if (parent->metaCast("AirPort_BrcmNIC") != nullptr)
                    {
                        controller = parent;
                        break;
                    }
                }
                name = skywalkName(interface);
                break;
        }
        if ((controller == nullptr) ||
            (controller->metaCast("AirPort_BrcmNIC") == nullptr) ||
            (name == nullptr) || (name[0] == 0) ||
            strnlen(name, kInterfaceNameCapacity) == kInterfaceNameCapacity)
        {
            return false;
        }
        bool supported = false;
        for (IOService const *parent = controller->getProvider();
             parent != nullptr; parent = parent->getProvider())
        {
            auto const *vendor =
                OSDynamicCast(OSData, parent->getProperty("vendor-id"));
            auto const *device =
                OSDynamicCast(OSData, parent->getProperty("device-id"));
            if ((vendor == nullptr) || (device == nullptr) ||
                vendor->getLength() != 4 || device->getLength() != 4)
            {
                continue;
            }
            uint32_t v {};
            uint32_t d {};
            memcpy(&v, vendor->getBytesNoCopy(), sizeof(v));
            memcpy(&d, device->getBytesNoCopy(), sizeof(d));
            static constexpr uint32_t ids[] = {
                0x4331, 0x4353, 0x43BA, 0x43A3, 0x43A0, 0x4357, 0x43B1, 0x43B2,
            };
            for (auto const id : ids)
            {
                supported |= v == kBroadcomPciVendor && d == id;
            }
            break;
        }
        if (!supported)
        {
            return false;
        }
        endpoint.interface = interface;
        endpoint.controller = controller;
        endpoint.kind = kind;
        strlcpy(static_cast<char *>(endpoint.name), name,
                sizeof(endpoint.name));
        return true;
    }

    using LocaleQuery = int (*)(IOService *, OSObject *, LocaleData *);
    using CountryCodeQuery = int (*)(IOService *, OSObject *,
                                     CountryCodeData *);
    using CountryProperty = void (*)(IOService *, bool);
    using DriverRequest = int (*)(IOService *, uint32_t, int, IOService *,
                                  void *);

    static LocaleQuery originalLocale;
    static CountryCodeQuery getCountryCode;
    static CountryProperty originalCountryProperty;
    static DriverRequest classicRequest;

    static int getLocale(IOService *controller, OSObject * /*unused*/,
                         LocaleData *output)
    {
        const auto result = originalLocale(controller, nullptr, output);
        if ((result != 0) || (output == nullptr) || output->version != 1 ||
            output->locale != localeUnknown)
        {
            return result;
        }
        CountryCodeData country {};
        if (getCountryCode(controller, nullptr, &country) == 0)
        {
            resolveLocale(*output, country);
        }
        return result;
    }

    static IOReturn updateCountryProperties(OSObject *target, void *argument,
                                            void *logging, void * /*unused*/,
                                            void * /*unused*/)
    {
        auto *controller = static_cast<IOService *>(target);
        auto *interface = static_cast<IOService *>(argument);
        originalCountryProperty(interface, *static_cast<bool *>(logging));
        LocaleData locale {};
        if (interface->isInactive() || controller->isInactive() ||
            (interface->getProperty("IO80211CountryCode") == nullptr) ||
            (classicRequest(controller, kCountryQuerySelector,
                            kCountryQueryType, interface, &locale) != 0) ||
            locale.version != 1)
        {
            interface->removeProperty("IO80211Locale");
        }
        else
        {
            interface->setProperty("IO80211Locale",
                                   localeString(locale.locale));
        }
        return kIOReturnSuccess;
    }

    static void updateCountryProperty(IOService *interface, bool logging)
    {
        auto *controller = classicController(interface);
        auto *loop =
            (controller != nullptr) ? controller->getWorkLoop() : nullptr;
        if ((controller == nullptr) ||
            (controller->metaCast("AirPort_BrcmNIC") == nullptr) ||
            (loop == nullptr))
        {
            originalCountryProperty(interface, logging);
            return;
        }
        if (loop->runAction(updateCountryProperties, controller, interface,
                            &logging) != kIOReturnSuccess)
        {
            originalCountryProperty(interface, logging);
            interface->removeProperty("IO80211Locale");
        }
    }

    using HardwareVersion = IOReturn (*)(IOService *, OSObject *, void *);
    static HardwareVersion originalHardwareVersion;

    static IOReturn getHardwareVersion(IOService *controller,
                                       OSObject *interface, void *output)
    {
        auto const result =
            originalHardwareVersion(controller, interface, output);
        if (result != kIOReturnSuccess || (output == nullptr))
        {
            return result;
        }
        auto *bytes = static_cast<uint8_t *>(output);
        uint16_t length = 0;
        memcpy(&length, bytes + 4, sizeof(length));
        auto *text = pointerFromAddress<char *>(
            pointerAddress(bytes + kHardwareTextOffset));
        HardwareIdentity identity {};
        if (readUInt32(bytes) != 1 || length >= kHardwareTextCapacity ||
            text[length] != '\0' ||
            !decodeHardwareIdentity(text, length, identity))
        {
            return result;
        }
        controller->setProperty("SimpleATHOriginalHardwareVersion", text);
        int count = 0;
        if (identity.boardVendor == kAppleBoardVendor)
        {
            count = snprintf(text, kHardwareTextCapacity,
                             "AirPort Extreme (0x%X, 0x%X)", identity.vendor,
                             identity.board);
        }
        else
        {
            count = snprintf(text, kHardwareTextCapacity,
                             "Broadcom ATH%u (%04x:%04x)", identity.chip,
                             identity.vendor, identity.device);
        }
        length = static_cast<uint16_t>(count);
        memcpy(bytes + 4, &length, sizeof(length));
        return result;
    }

    static IOReturn newClassicClient(IOService *self, task_t task, void *token,
                                     uint32_t type, OSDictionary *properties,
                                     IOUserClient **result)
    {
        auto const status =
            (type != 0U) || !Bridge::ready()
                ? originalClassicClient(self, task, token, type, properties,
                                        result)
                : ATH80211UserClient::create(self, task, token, properties,
                                             InterfaceKind::Classic, result);
        return wrapNativeUserClient(status, task, token, type, properties,
                                    result);
    }

    static IOReturn newVirtualClient(IOService *self, task_t task, void *token,
                                     uint32_t type, OSDictionary *properties,
                                     IOUserClient **result)
    {
        auto const status =
            (type != 0U) || !Bridge::ready()
                ? originalVirtualClient(self, task, token, type, properties,
                                        result)
                : ATH80211UserClient::create(self, task, token, properties,
                                             InterfaceKind::Virtual, result);
        return wrapNativeUserClient(status, task, token, type, properties,
                                    result);
    }

    static IOReturn newSkywalkClient(IOService *self, task_t task, void *token,
                                     uint32_t type, OSDictionary *properties,
                                     IOUserClient **result)
    {
        auto const status =
            (type != 0U) || !Bridge::ready() ||
                    (self->metaCast("ATHLegacyInterface") == nullptr)
                ? originalSkywalkClient(self, task, token, type, properties,
                                        result)
                : ATH80211UserClient::create(self, task, token, properties,
                                             InterfaceKind::Skywalk, result);
        return wrapNativeUserClient(status, task, token, type, properties,
                                    result);
    }

    IOReturn createSkywalkUserClient(IOService *self, task_t task, void *token,
                                     uint32_t type, OSDictionary *properties,
                                     IOUserClient **result)
    {
        return newSkywalkClient(self, task, token, type, properties, result);
    }

    void Bridge::enableNativeSkywalk()
    {
        originalSkywalkClient = createSkywalkUserClient;
        __atomic_fetch_or(&state, 2U, __ATOMIC_RELEASE);
    }

    bool Bridge::addClient(ATH80211UserClient *client)
    {
        bool added = false;
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        for (auto &entry : clients)
        {
            if (entry == nullptr)
            {
                client->retain();
                entry = client;
                added = true;
                break;
            }
        }
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        return added;
    }

    void Bridge::removeClient(ATH80211UserClient *client)
    {
        ATH80211UserClient const *removed = nullptr;
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        for (auto &entry : clients)
        {
            if (entry == client)
            {
                removed = entry;
                entry = nullptr;
                break;
            }
        }
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        if (removed != nullptr)
        {
            removed->release();
        }
    }

    static int readEventValue(const Endpoint &endpoint, uint32_t type,
                              uint8_t *buffer, size_t length,
                              uint32_t *value = nullptr)
    {
        LegacyRequest request {};
        strlcpy(static_cast<char *>(request.request.interfaceName),
                static_cast<const char *>(endpoint.name),
                sizeof(request.request.interfaceName));
        request.request.type = static_cast<int32_t>(type);
        request.request.length = static_cast<uint32_t>(length);
        request.request.data = pointerAddress(buffer);
        request.pointerSize = sizeof(uint64_t);
        const auto result =
            Bridge::command(endpoint, false, request, buffer, length);
        if ((result == 0) && (value == nullptr) &&
            request.request.length != length)
        {
            return EINVAL;
        }
        if ((result == 0) && (value != nullptr))
        {
            *value = static_cast<uint32_t>(request.request.value);
        }
        return result;
    }

    static IOReturn captureJoinEvent(OSObject * /*unused*/, void *argument,
                                     void * /*unused*/, void * /*unused*/,
                                     void * /*unused*/)
    {
        auto *event = static_cast<PendingEvent *>(argument);
        Endpoint endpoint {
            event->interface,
            event->controller,
            InterfaceKind::Classic,
            {},
        };
        strlcpy(static_cast<char *>(endpoint.name),
                static_cast<const char *>(event->name), sizeof(endpoint.name));
        uint8_t buffer[kAssociationAddressBytes] {};
        uint32_t status {};
        uint32_t result {};
        auto error = readEventValue(endpoint, kAssociationStatusSelector,
                                    static_cast<uint8_t *>(buffer),
                                    sizeof(uint32_t), &status);
        if (error == 0)
        {
            error = readEventValue(endpoint, kAssociationResultSelector,
                                   static_cast<uint8_t *>(buffer),
                                   sizeof(uint32_t), &result);
        }
        if ((error == 0) && result == 1)
        {
            error =
                readEventValue(endpoint, kAssociationAddressSelector,
                               static_cast<uint8_t *>(buffer), sizeof(buffer));
        }
        __atomic_store_n(&counters.lastAssociationEventReadResult,
                         static_cast<uint32_t>(error), __ATOMIC_RELAXED);
        if (error != 0)
        {
            __atomic_fetch_add(&counters.associationEventReadErrors, 1ULL,
                               __ATOMIC_RELAXED);
            return static_cast<IOReturn>(error);
        }
        if (encodeJoinStatus(status, result,
                             static_cast<const uint8_t *>(buffer),
                             result == 1 ? sizeof(buffer) : 0,
                             static_cast<uint8_t *>(event->payload),
                             sizeof(event->payload), Bridge::abi()))
        {
            event->length = static_cast<uint32_t>(Bridge::abi().joinStatusSize);
            __atomic_fetch_add(&counters.associationEventConversions, 1ULL,
                               __ATOMIC_RELAXED);
        }
        return kIOReturnSuccess;
    }

    static void drainEvents(thread_call_param_t /*unused*/,
                            thread_call_param_t /*unused*/)
    {
        PendingEvent event {};
        for (;;)
        {
            ATH80211UserClient *targets[kClientCapacity];
            size_t count = 0;
            const auto interruptState =
                IOSimpleLockLockDisableInterrupt(hubLock);
            if (pendingRead == pendingWrite)
            {
                IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
                return;
            }
            memcpy(&event, &pending[pendingRead], sizeof(event));
            pendingRead = (pendingRead + 1) % kPendingCapacity;
            for (auto *client : clients)
            {
                if (client != nullptr)
                {
                    client->retain();
                    targets[count++] = client;
                }
            }
            IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
            if (event.interface != nullptr)
            {
                auto *loop = event.controller->getWorkLoop();
                if (loop != nullptr)
                {
                    loop->runAction(captureJoinEvent, event.controller, &event);
                }
                event.interface->release();
            }
            for (size_t index = 0; index < count; ++index)
            {
                targets[index]->receive(
                    event.controller, static_cast<const char *>(event.name),
                    event.event, static_cast<const uint8_t *>(event.payload),
                    event.length, event.seconds, event.microseconds,
                    event.serial);
                targets[index]->release();
            }
            event.controller->release();
        }
    }

    static void queueEvent(IOService *self, InterfaceKind kind,
                           uint32_t message, void *payload, size_t length,
                           bool powerSnapshot = false)
    {
        if (!Bridge::ready())
        {
            return;
        }
        Endpoint endpoint {};
        if (length > maximumEventPayload ||
            ((length != 0U) && (payload == nullptr)) ||
            !Bridge::identify(self, kind, endpoint))
        {
            __atomic_fetch_add(&counters.dropped, 1ULL, __ATOMIC_RELAXED);
            return;
        }
        const auto &abi = Bridge::abi();
        const auto outputLength =
            static_cast<uint32_t>(eventPayloadSize(message, length, abi));
        clock_sec_t seconds = 0;
        clock_usec_t microseconds = 0;
        clock_get_calendar_microtime(&seconds, &microseconds);
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        const auto eventSerial =
            __atomic_add_fetch(&serial, 1ULL, __ATOMIC_RELEASE);
        if (message == driverAvailableEvent)
        {
            size_t slot = arrsize(availability);
            for (size_t index = 0; index < arrsize(availability); ++index)
            {
                if ((availability[index].controller != nullptr) &&
                    availability[index].controller == endpoint.controller &&
                    (strncmp(
                         static_cast<const char *>(availability[index].name),
                         static_cast<const char *>(endpoint.name),
                         sizeof(endpoint.name)) == 0))
                {
                    slot = index;
                    break;
                }
                if ((availability[index].controller == nullptr) &&
                    slot == arrsize(availability))
                {
                    slot = index;
                }
            }
            if (powerSnapshot && slot == arrsize(availability))
            {
                IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
                return;
            }
            if (slot < arrsize(availability))
            {
                auto &saved = availability[slot];
                if (powerSnapshot &&
                    (saved.original ||
                     (saved.event.length == abi.driverAvailableSize &&
                      readUInt32(
                          static_cast<const uint8_t *>(saved.event.payload) +
                          kPowerSnapshotWordOffset) ==
                          readUInt32(static_cast<uint8_t *>(payload) +
                                     kPowerSnapshotWordOffset))))
                {
                    IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
                    return;
                }
                if (saved.controller == nullptr)
                {
                    saved.controller = endpoint.controller;
                    saved.controller->retain();
                    strlcpy(static_cast<char *>(saved.name),
                            static_cast<const char *>(endpoint.name),
                            sizeof(saved.name));
                }
                saved.event.length = 0;
                saved.original =
                    !powerSnapshot && outputLength == abi.driverAvailableSize;
                if (outputLength == abi.driverAvailableSize)
                {
                    copyEventPayload(
                        message, payload, length,
                        static_cast<uint8_t *>(saved.event.payload),
                        sizeof(saved.event.payload), abi);
                    saved.event.length = outputLength;
                    saved.event.seconds = seconds;
                    saved.event.microseconds = microseconds;
                }
            }
            __atomic_fetch_add(powerSnapshot ? &counters.powerAvailabilityEvents
                                             : &counters.availabilityEvents,
                               1ULL, __ATOMIC_RELAXED);
        }
        if (message == associationDoneEvent)
        {
            __atomic_fetch_add(&counters.associationEvents, 1ULL,
                               __ATOMIC_RELAXED);
            __atomic_store_n(&counters.lastAssociationEventLength,
                             static_cast<uint32_t>(length), __ATOMIC_RELAXED);
        }
        const auto next = (pendingWrite + 1) % kPendingCapacity;
        if (next == pendingRead)
        {
            IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
            __atomic_fetch_add(&counters.dropped, 1ULL, __ATOMIC_RELAXED);
            return;
        }
        auto &entry = pending[pendingWrite];
        entry.serial = eventSerial;
        entry.controller = endpoint.controller;
        entry.controller->retain();
        entry.interface = abi.joinEventPolicy != JoinEventPolicy::Passthrough &&
                                  message == associationDoneEvent &&
                                  (length == 0U) &&
                                  kind == InterfaceKind::Classic
                              ? self
                              : nullptr;
        if (entry.interface != nullptr)
        {
            entry.interface->retain();
        }
        strlcpy(static_cast<char *>(entry.name),
                static_cast<const char *>(endpoint.name), sizeof(entry.name));
        entry.event = message;
        entry.length = outputLength;
        entry.seconds = seconds;
        entry.microseconds = microseconds;
        copyEventPayload(message, payload, length,
                         static_cast<uint8_t *>(entry.payload),
                         sizeof(entry.payload), abi);
        pendingWrite = next;
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        __atomic_fetch_add(&counters.events, 1ULL, __ATOMIC_RELAXED);
        if (message == scanDoneEvent)
        {
            __atomic_fetch_add(&counters.scanDoneEvents, 1ULL,
                               __ATOMIC_RELAXED);
        }
        thread_call_enter(eventCall);
    }

    int Bridge::refreshAvailability(const Endpoint &endpoint)
    {
        if (endpoint.kind != InterfaceKind::Classic)
        {
            return ENOTSUP;
        }
        uint8_t power[powerDataSize] {};
        return readEventValue(endpoint, kPowerAvailabilitySelector,
                              static_cast<uint8_t *>(power), sizeof(power));
    }

    uint64_t Bridge::copyAvailability(const Endpoint &endpoint,
                                      AvailabilityEvent &event)
    {
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        const auto boundary = __atomic_load_n(&serial, __ATOMIC_ACQUIRE);
        event.length = 0;
        for (const auto &saved : availability)
        {
            if (saved.controller == endpoint.controller &&
                (strncmp(saved.name, endpoint.name, sizeof(endpoint.name)) ==
                 0))
            {
                event = saved.event;
                break;
            }
        }
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        return boundary;
    }

    static IOReturn postClassic(IOService *self, uint32_t message,
                                void *payload, size_t length)
    {
        queueEvent(self, InterfaceKind::Classic, message, payload, length);
        return originalClassicEvent(self, message, payload, length);
    }

    static IOReturn postVirtual(IOService *self, uint32_t message,
                                void *payload, size_t length)
    {
        queueEvent(self, InterfaceKind::Virtual, message, payload, length);
        return originalVirtualEvent(self, message, payload, length);
    }

    static IOReturn postInfra(IOService *self, uint32_t message, void *payload,
                              size_t length)
    {
        queueEvent(self, InterfaceKind::Skywalk, message, payload, length);
        return originalInfraEvent(self, message, payload, length);
    }

    int Bridge::command(const Endpoint &endpoint, bool set,
                        LegacyRequest &request, void *shadow, size_t size)
    {
        // Reject incomplete or forged endpoints before dereferencing a
        // controller or selecting an unrelated native ioctl callback.
        if ((endpoint.interface == nullptr) ||
            (endpoint.controller == nullptr) ||
            (size != 0 && (shadow == nullptr)) ||
            (endpoint.kind != InterfaceKind::Classic &&
             endpoint.kind != InterfaceKind::Virtual &&
             endpoint.kind != InterfaceKind::Skywalk))
        {
            return EINVAL;
        }
        if (!ready() || endpoint.interface->isInactive() ||
            endpoint.controller->isInactive())
        {
            return ENXIO;
        }
        if ((endpoint.kind == InterfaceKind::Classic &&
             (classicCommand == nullptr)) ||
            (endpoint.kind != InterfaceKind::Classic &&
             ((set ? setRequest : getRequest) == nullptr)))
        {
            return ENXIO;
        }
        CopyContext context {
            current_thread(),
            pointerAddress(shadow),
            size,
            nullptr,
        };
        IOSimpleLockLock(contextLock);
        context.next = contexts;
        contexts = &context;
        IOSimpleLockUnlock(contextLock);
        const auto result =
            endpoint.kind == InterfaceKind::Classic
                ? classicCommand(endpoint.interface, endpoint.controller,
                                 set ? setCommand : getCommand, nullptr,
                                 &request.request)
                : (set ? setRequest : getRequest)(
                      endpoint.controller, nullptr,
                      endpoint.kind == InterfaceKind::Virtual ? endpoint.interface : nullptr,
                      endpoint.kind == InterfaceKind::Skywalk ? endpoint.interface : nullptr,
                      &request);
        IOSimpleLockLock(contextLock);
        for (auto *cursor = &contexts; (*cursor) != nullptr;
             cursor = &(*cursor)->next)
        {
            if (*cursor == &context)
            {
                *cursor = context.next;
                break;
            }
        }
        IOSimpleLockUnlock(contextLock);
        if (!set && request.request.type == kPowerAvailabilitySelector &&
            endpoint.kind == InterfaceKind::Classic)
        {
            __atomic_store_n(&counters.lastAvailabilityReadResult,
                             static_cast<uint32_t>(result), __ATOMIC_RELAXED);
            uint8_t event[nativeDriverAvailableSize];
            if ((result == 0) && size >= powerDataSize &&
                request.request.length == powerDataSize &&
                encodePowerAvailability(
                    static_cast<const uint8_t *>(shadow), powerDataSize,
                    static_cast<uint8_t *>(event), sizeof(event), abi()))
            {
                queueEvent(endpoint.interface, endpoint.kind,
                           driverAvailableEvent, static_cast<uint8_t *>(event),
                           abi().driverAvailableSize, true);
            }
        }
        return result;
    }

    static bool validate(mach_vm_address_t address, size_t size,
                         const ByteGuard *guards, size_t count)
    {
        // A malformed mapped span must not wrap the native address space or
        // authorize guard-table access through a missing descriptor pointer.
        if (address == 0U || size < sizeof(mach_header_64) ||
            size > UINTPTR_MAX - address || (count != 0U && guards == nullptr))
        {
            return false;
        }
        const auto *header =
            pointerFromAddress<const mach_header_64 *>(address);
        if (header->magic != MH_MAGIC_64 ||
            header->cputype != CPU_TYPE_X86_64 ||
            header->ncmds > kMaximumMachLoadCommands ||
            header->sizeofcmds > size - sizeof(*header))
        {
            return false;
        }
        const auto end = address + sizeof(*header) + header->sizeofcmds;
        auto cursor = address + sizeof(*header);
        for (uint32_t index = 0; index < header->ncmds; ++index)
        {
            if (cursor > end || end - cursor < sizeof(load_command))
            {
                return false;
            }
            const auto *cmd = pointerFromAddress<const load_command *>(cursor);
            if (cmd->cmdsize < sizeof(*cmd) || cmd->cmdsize > end - cursor)
            {
                return false;
            }
            cursor += cmd->cmdsize;
        }
        for (size_t i = 0; i < count; ++i)
        {
            const auto &guard = guards[i];
            if (!contains(address, size, address + guard.offset,
                          sizeof(guard.bytes)))
            {
                return false;
            }
            const auto *actual =
                pointerFromAddress<const uint8_t *>(address + guard.offset);
            for (size_t byte = 0; byte < sizeof(guard.bytes); ++byte)
            {
                if ((actual[byte] & guard.mask[byte]) !=
                    (guard.bytes[byte] & guard.mask[byte]))
                {
                    return false;
                }
            }
        }
        return true;
    }

    static mach_vm_address_t followBranch(mach_vm_address_t address)
    {
        for (unsigned i = 0; i < 3; ++i)
        {
            const auto *bytes = pointerFromAddress<const uint8_t *>(address);
            int32_t offset = 0;
            if (bytes[0] == kJmpRel32Opcode)
            {
                memcpy(&offset, bytes + 1, sizeof(offset));
                address += kRel32CallLength + offset;
            }
            else if (bytes[0] == kJmpIndirectOpcode &&
                     bytes[1] == kJmpRipRelativeMode)
            {
                memcpy(&offset, bytes + 2, sizeof(offset));
                memcpy(&address,
                       bytes + kRipRelativeBranchTargetOffset + offset,
                       sizeof(address));
            }
            else
            {
                return address;
            }
        }
        return address;
    }

    static bool patchCopies(KernelPatcher &patcher, mach_vm_address_t address,
                            size_t size, const CopySite *sites, size_t count)
    {
        if (count > kCopySiteCapacity)
        {
            return false;
        }
        const auto input =
            patcher.solveSymbol(KernelPatcher::KernelID, "_copyin");
        const auto output =
            patcher.solveSymbol(KernelPatcher::KernelID, "_copyout");
        if ((input == 0U) || (output == 0U))
        {
            patcher.clearError();
            return false;
        }
        int32_t offsets[kCopySiteCapacity];
        for (size_t i = 0; i < count; ++i)
        {
            const auto &site = sites[i];
            auto const call = address + site.offset;
            if (!contains(address, size, call, kRel32CallLength) ||
                *pointerFromAddress<uint8_t *>(call) != kCallRel32Opcode)
            {
                return false;
            }
            int32_t old = 0;
            memcpy(&old, pointerFromAddress<void *>(call + 1), sizeof(old));
            if (followBranch(call + kRel32CallLength + old) !=
                followBranch(site.output ? output : input))
            {
                return false;
            }
            auto target = site.output ? pointerAddress(bridgeCopyOut)
                                      : pointerAddress(bridgeCopyIn);
            target = patcher.branchTarget(target, call + kRel32CallLength);
            if (target == 0U)
            {
                return false;
            }
            auto const delta =
                static_cast<int64_t>(target - (call + kRel32CallLength));
            if (delta < INT32_MIN || delta > INT32_MAX)
            {
                return false;
            }
            offsets[i] = static_cast<int32_t>(delta);
        }
        for (size_t i = 0; i < count; ++i)
        {
            memcpy(pointerFromAddress<void *>(address + sites[i].offset + 1),
                   &offsets[i], sizeof(offsets[i]));
        }
        return true;
    }

    void Bridge::disable(const char *reason)
    {
        reject(reason);
    }

    bool Bridge::prepareImage(LinkedImage &image, size_t index)
    {
        if (index >= 2 || !image.editable || (activeABI == nullptr))
        {
            return false;
        }
        KernelPatcher patcher(image);
        patchImage(patcher, index, image.address, image.payload->mappedSize);
        return (__atomic_load_n(&state, __ATOMIC_ACQUIRE) &
                kDisabledStateBit) == 0U;
    }

    void Bridge::patchImage(KernelPatcher &patcher, size_t index,
                            mach_vm_address_t address, size_t size)
    {
        if ((__atomic_load_n(&state, __ATOMIC_ACQUIRE) & kDisabledStateBit) !=
            0U)
        {
            return;
        }
        if (index == 0)
        {
            if (!validate(address, size,
                          static_cast<const ByteGuard *>(kLegacyGuards),
                          arrsize(kLegacyGuards)))
            {
                reject("LegacyBinaryMismatch");
                return;
            }
            getRequest = pointerFromAddress<Ioctl>(patcher.solveSymbol(
                index, "__ZN17IO80211Controller20apple80211_ioctl_"
                       "getEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO8"
                       "0211SkywalkInterfacePv"));
            setRequest = pointerFromAddress<Ioctl>(patcher.solveSymbol(
                index, "__ZN17IO80211Controller20apple80211_ioctl_"
                       "setEP16IO80211InterfaceP23IO80211VirtualInterfaceP23IO8"
                       "0211SkywalkInterfacePv"));
            classicController =
                pointerFromAddress<Controller>(patcher.solveSymbol(
                    index, "__ZN16IO80211Interface13getControllerEv"));
            virtualController =
                pointerFromAddress<Controller>(patcher.solveSymbol(
                    index, "__ZN23IO80211VirtualInterface13getControllerEv"));
            classicName = pointerFromAddress<BSDName>(patcher.solveSymbol(
                index, "__ZN16IO80211Interface10getBSDNameEv"));
            virtualName = pointerFromAddress<BSDName>(patcher.solveSymbol(
                index, "__ZN23IO80211VirtualInterface10getBSDNameEv"));
            skywalkName = pointerFromAddress<BSDName>(patcher.solveSymbol(
                index, "__ZN23IO80211SkywalkInterface10getBSDNameEv"));
            classicCommand = pointerFromAddress<PerformCommand>(
                patcher.solveSymbol(index, "__"
                                           "ZN16IO80211Interface14performComman"
                                           "dEP19IONetworkControllermPvS2_"));
            classicRequest =
                pointerFromAddress<DriverRequest>(patcher.solveSymbol(
                    index, "__"
                           "ZN17IO80211Controller22apple80211RequestIoctlEjiP16"
                           "IO80211InterfacePv"));
            if ((getRequest == nullptr) || (setRequest == nullptr) ||
                (classicController == nullptr) ||
                (virtualController == nullptr) || (classicName == nullptr) ||
                (virtualName == nullptr) || (skywalkName == nullptr) ||
                (classicCommand == nullptr) || (classicRequest == nullptr))
            {
                patcher.clearError();
                reject("LegacySymbolsMissing");
                return;
            }
            KernelPatcher::RouteRequest routes[] = {
                {
                    "__"
                    "ZN16IO80211Interface13newUserClientEP4taskPvjP12OSDictiona"
                    "ryP"
                    "P12IOUserClient",
                    newClassicClient,
                    originalClassicClient,
                },
                {
                    "__"
                    "ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSD"
                    "ict"
                    "ionaryPP12IOUserClient",
                    newVirtualClient,
                    originalVirtualClient,
                },
                {
                    "__ZN16IO80211Interface27IO80211InterfacePostMessageEjPvm",
                    postClassic,
                    originalClassicEvent,
                },
                {
                    "__"
                    "ZN23IO80211VirtualInterface27IO80211InterfacePostMessageEj"
                    "Pv"
                    "m",
                    postVirtual,
                    originalVirtualEvent,
                },
                {
                    "__ZN21IO80211InfraInterface19postMessageInternalEjPvm",
                    postInfra,
                    originalInfraEvent,
                },
                {
                    "__ZN16IO80211Interface25updateCountryCodePropertyEb",
                    updateCountryProperty,
                    originalCountryProperty,
                },
            };
            if (!patcher.routeMultipleLong(index, routes, address, size) ||
                !patchCopies(patcher, address, size,
                             static_cast<const CopySite *>(kLegacyCopySites),
                             arrsize(kLegacyCopySites)))
            {
                patcher.clearError();
                reject("LegacyRoutingFailed");
                return;
            }
            __atomic_fetch_or(&state, 1U, __ATOMIC_RELEASE);
        }
        else if (index == 1)
        {
            const bool original = abi().backend == AirPortBackend::Original;
            const auto *const guards =
                original
                    ? static_cast<const ByteGuard *>(kAirPortOriginalGuards)
                    : static_cast<const ByteGuard *>(kAirPortGuards);
            const auto guardCount = original ? arrsize(kAirPortOriginalGuards)
                                             : arrsize(kAirPortGuards);
            const auto *const copies =
                original
                    ? static_cast<const CopySite *>(kAirPortOriginalCopySites)
                    : static_cast<const CopySite *>(kAirPortCopySites);
            const auto copyCount = original ? arrsize(kAirPortOriginalCopySites)
                                            : arrsize(kAirPortCopySites);
            if (!validate(address, size, guards, guardCount))
            {
                reject(original ? "OriginalAirPortBinaryMismatch"
                                : "TahoeAirPortBinaryMismatch");
                return;
            }
            if (!patchCopies(patcher, address, size, copies, copyCount))
            {
                patcher.clearError();
                reject("AirPortCopyRoutingFailed");
                return;
            }
            getCountryCode =
                pointerFromAddress<CountryCodeQuery>(patcher.solveSymbol(
                    index, "__ZN15AirPort_BrcmNIC15getCOUNTRY_"
                           "CODEEP8OSObjectP28apple80211_country_code_data"));
            if (getCountryCode == nullptr)
            {
                patcher.clearError();
                reject("CountryCodeSymbolMissing");
                return;
            }
            KernelPatcher::RouteRequest routes[] = {
                {
                    "__ZN15AirPort_BrcmNIC19getHARDWARE_"
                    "VERSIONEP8OSObjectP23apple80211_version_data",
                    getHardwareVersion,
                    originalHardwareVersion,
                },
                {
                    "__ZN15AirPort_BrcmNIC9getLOCALEEP8OSObjectP22apple80211_"
                    "locale_data",
                    getLocale,
                    originalLocale,
                },
            };
            if (!patcher.routeMultipleLong(index, routes, address, size))
            {
                patcher.clearError();
                reject("AirPortQueryRoutingFailed");
                return;
            }
            __atomic_fetch_or(&state, 4U, __ATOMIC_RELEASE);
        }
        if (ready())
        {
            __atomic_store_n(&failure, "ReadyForHardwareValidation",
                             __ATOMIC_RELEASE);
            SYSLOG("bridge", "%s ABI bridge ready", abi().name);
        }
    }

    void Bridge::initialize()
    {
        activeABI = userABIForKernel(static_cast<uint32_t>(getKernelVersion()));
        if (activeABI == nullptr)
        {
            reject("UnsupportedKernel");
            return;
        }
        contextLock = IOSimpleLockAlloc();
        hubLock = IOSimpleLockAlloc();
        pending = static_cast<PendingEvent *>(
            IOMalloc(sizeof(PendingEvent) * kPendingCapacity));
        eventCall = thread_call_allocate_with_options(
            drainEvents, nullptr, THREAD_CALL_PRIORITY_KERNEL,
            THREAD_CALL_OPTIONS_ONCE);
        if ((contextLock == nullptr) || (hubLock == nullptr) ||
            (pending == nullptr) || (eventCall == nullptr))
        {
            reject("AllocationFailed");
            return;
        }
    }

    void Bridge::trackController(IOService *controller)
    {
        if ((controller == nullptr) || (hubLock == nullptr))
        {
            return;
        }
        const auto interruptState = IOSimpleLockLockDisableInterrupt(hubLock);
        if (observedController == nullptr)
        {
            controller->retain();
            observedController = controller;
        }
        IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
    }

    void Bridge::publish(IOService *service)
    {
        service->setProperty("Status",
                             __atomic_load_n(&failure, __ATOMIC_ACQUIRE));
        service->setProperty("PatchState",
                             __atomic_load_n(&state, __ATOMIC_ACQUIRE),
                             kNumberBits32);
        service->setProperty("SupportedKernel", "23.x / 24.x / 25.x");
        service->setProperty("AdapterVersion", "1.2.0");
        service->setProperty("NativePowerDomainPatched", false);
        IOService const *controller = nullptr;
        if (hubLock != nullptr)
        {
            const auto interruptState =
                IOSimpleLockLockDisableInterrupt(hubLock);
            controller = observedController;
            if (controller != nullptr)
            {
                controller->retain();
            }
            IOSimpleLockUnlockEnableInterrupt(hubLock, interruptState);
        }
        if (controller != nullptr)
        {
            service->setProperty(
                "WirelessControllerIdentity",
                (controller->metaCast("AirPortDriver") != nullptr)
                    ? "AirPortDriver"
                    : "Unrecognized");
            // A metaCast is not a layout or object-size contract. The old
            // fixed-offset power fields could read past an unknown Tahoe
            // controller allocation; publish no unverified raw snapshot.
            service->setProperty("BrcmPowerSnapshotAvailable", false);
            controller->release();
        }
        service->setProperty("ActiveABI", (activeABI != nullptr)
                                              ? activeABI->name
                                              : "Unsupported");
        const char *backendName = "Unsupported";
        if (activeABI != nullptr)
        {
            backendName = activeABI->backend == AirPortBackend::Original
                              ? "Original"
                              : "Tahoe";
        }
        service->setProperty("AirPortBackend", backendName);
        service->setProperty("DriverKitBackend", false);

        struct Metric
        {
                const char *name;
                uint64_t *value;
        } const metrics[] = {
            {"Opens", &counters.opens},
            {"DeniedOpens", &counters.denied},
            {"Commands", &counters.commands},
            {"CommandErrors", &counters.errors},
            {"Events", &counters.events},
            {"DroppedEvents", &counters.dropped},
            {"Notifications", &counters.notifications},
            {"NotificationErrors", &counters.notificationErrors},
            {"ScanRecords", &counters.scanRecords},
            {"ScanDoneEvents", &counters.scanDoneEvents},
            {"ScanDoneRecords", &counters.scanDoneRecords},
            {"AssociationRequests", &counters.associationRequests},
            {"AssociationAccepted", &counters.associationAccepted},
            {"DriverAvailabilityEvents", &counters.availabilityEvents},
            {"DriverAvailabilityReplays", &counters.availabilityReplays},
            {"AssociationEvents", &counters.associationEvents},
            {
                "AssociationEventConversions",
                &counters.associationEventConversions,
            },
            {
                "AssociationEventReadErrors",
                &counters.associationEventReadErrors,
            },
            {"PowerAvailabilityEvents", &counters.powerAvailabilityEvents},
        };

        for (const auto &metric : metrics)
        {
            service->setProperty(
                metric.name, __atomic_load_n(metric.value, __ATOMIC_RELAXED),
                kNumberBits64);
        }
        for (size_t i = 0; i < arrsize(counters.selectors); ++i)
        {
            char name[kMetricNameCapacity];
            snprintf(static_cast<char *>(name), sizeof(name), "Selector%u",
                     static_cast<unsigned>(i));
            service->setProperty(
                static_cast<const char *>(name),
                __atomic_load_n(&counters.selectors[i], __ATOMIC_RELAXED),
                kNumberBits64);
        }
        service->setProperty(
            "LastRequest",
            __atomic_load_n(&counters.lastRequest, __ATOMIC_RELAXED),
            kNumberBits32);
        service->setProperty(
            "LastResult",
            __atomic_load_n(&counters.lastResult, __ATOMIC_RELAXED),
            kNumberBits32);
        service->setProperty(
            "LastAssociationResult",
            __atomic_load_n(&counters.lastAssociationResult, __ATOMIC_RELAXED),
            kNumberBits32);
        service->setProperty(
            "LastAssociationEventLength",
            __atomic_load_n(&counters.lastAssociationEventLength,
                            __ATOMIC_RELAXED),
            kNumberBits32);
        service->setProperty(
            "LastAssociationEventReadResult",
            __atomic_load_n(&counters.lastAssociationEventReadResult,
                            __ATOMIC_RELAXED),
            kNumberBits32);
        service->setProperty(
            "LastAvailabilityReadResult",
            __atomic_load_n(&counters.lastAvailabilityReadResult,
                            __ATOMIC_RELAXED),
            kNumberBits32);
    }

} // namespace ath
