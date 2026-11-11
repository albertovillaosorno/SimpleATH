// Copyright:
//   - Copyright © 2026 laobamac. All rights reserved.
// SPDX-License-Identifier:
//   - LicenseRef-SimpleBCM-All-Rights-Reserved
// Confidential:
//   - false
// License-File:
//   - LICENSE-SIMPLEBCM
// Provenance:
//   - SimpleBCM v1.2.0, by laobamac; no public license grant identified
//   - Originally authored by laobamac on 2026/11/1.
//
// Boundary-Contract:
// - Owns:
//   - Native driver contracts and implementation for native user client.
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
//   - Native driver contracts and implementation for native user client.
// - Description:
//   - Implements or verifies the NativeUserClient source boundary.
// - Usage:
//   - Called through the native driver interface with explicit lifecycle state.
// - Defaults:
//   - Missing evidence, invalid input, or unsupported states fail closed.
//
// Module: Native driver contracts and implementation for native user client.

#include "NativeUserClient.hpp"
#include "NativeProfile.hpp"
#include "Payload.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTypes.h>
#include <IOKit/IOUserClient.h>
#include <libkern/c++/OSBoolean.h>
#include <libkern/c++/OSObject.h>
#include <mach/mach_types.h>
#include <mach/port.h>
#include <stdint.h>
#include <string.h>

namespace ath
{

    namespace
    {
        constexpr size_t kClientProfileCount = 2U;
        constexpr size_t kNativeClientSlots = 300U;
        constexpr size_t kVtableHeaderSlots = 2U;
        constexpr size_t kNativeClientViewSlots =
            kNativeClientSlots + kVtableHeaderSlots;
        constexpr size_t kClientContextOffset = 224U;
        constexpr size_t kClientWrapperBytes = 232U;
        constexpr size_t kSlotBytes = sizeof(uintptr_t);
        constexpr size_t kVtableDestructorSlot = 2U;
        constexpr size_t kVtableDeletingDestructorSlot = 3U;
        constexpr size_t kFreeSlot = 2U + (0x90U / kSlotBytes);
        constexpr size_t kStartSlot = 2U + (0x5C0U / kSlotBytes);
        constexpr size_t kStopSlot = 2U + (0x5C8U / kSlotBytes);
        constexpr size_t kExternalMethodSlot = 2U + (0x850U / kSlotBytes);
        constexpr size_t kNotify64Slot = 2U + (0x858U / kSlotBytes);
        constexpr size_t kInitSlot = 2U + (0x8E0U / kSlotBytes);
        constexpr size_t kCloseSlot = 2U + (0x8F0U / kSlotBytes);
        constexpr size_t kDiedSlot = 2U + (0x8F8U / kSlotBytes);
        constexpr size_t kServiceSlot = 2U + (0x900U / kSlotBytes);
        constexpr size_t kNotify32Slot = 2U + (0x908U / kSlotBytes);
        constexpr size_t kMemorySlot = 2U + (0x920U / kSlotBytes);

        struct ClientContext
        {
                IOUserClient *implementation {nullptr};
                uint32_t profile {0U};
                uint32_t closed {0U};
        };

        static_assert(
            sizeof(ClientContext) ==
                sizeof(IOUserClient *) + (2U * sizeof(uint32_t)),
            "Native wrapper context must retain pinned pointer layout");

        struct ClientDispatchState
        {
                uintptr_t views[kClientProfileCount][kNativeClientViewSlots] {};
                bool prepared {false};
        };

        ClientDispatchState &dispatchState()
        {
            static ClientDispatchState state {};
            return state;
        }

        template <typename T, size_t N>
        T &checkedAt(T (&items)[N], size_t index)
        {
            for (T &item : items)
            {
                if (index == 0U)
                {
                    return item;
                }
                --index;
            }
            __builtin_trap(); // Caller validates all runtime slot indexes.
        }

        void *clientContextField(const IOUserClient *self)
        {
            uintptr_t address = 0U;
            static_assert(sizeof(const IOUserClient *) == sizeof(address),
                          "Native user-client pointer must fit uintptr_t");
            __builtin_memcpy(&address, static_cast<const void *>(&self),
                             sizeof(address));
            if (address > UINTPTR_MAX - kClientContextOffset)
            {
                return nullptr;
            }
            address += kClientContextOffset;
            void *field = nullptr;
            __builtin_memcpy(static_cast<void *>(&field), &address,
                             sizeof(field));
            return field;
        }

        ClientContext *context(const IOUserClient *self)
        {
            ClientContext *result = nullptr;
            const void *const field = clientContextField(self);
            if (field != nullptr)
            {
                __builtin_memcpy(static_cast<void *>(&result), field,
                                 sizeof(ClientContext *));
            }
            return result;
        }

        void setContext(const IOUserClient *self, const ClientContext *value)
        {
            void *const field = clientContextField(self);
            if (field != nullptr)
            {
                __builtin_memcpy(field, static_cast<const void *>(&value),
                                 sizeof(ClientContext *));
            }
        }

        NativeClientProfile profileFor(uint32_t index)
        {
            NativeClientProfile result {};
            if (index < kClientProfileCount)
            {
                (void)detail::readAt(&nativeClientProfiles[0U], index, result);
            }
            return result;
        }

        template <typename Method> Method native(uint32_t index)
        {
            uintptr_t value = 0U;
            (void)detail::readAt(&athNativeImports[0U], index, value);
            static_assert(sizeof(Method) == sizeof(value),
                          "Native method pointer must fit imported slot");
            Method result {};
            __builtin_memcpy(static_cast<void *>(&result), &value,
                             sizeof(value));
            return result;
        }

        template <typename Function, size_t N>
        void setMethod(uintptr_t (&view)[N], size_t slot, Function function)
        {
            static_assert(sizeof(function) == sizeof(uintptr_t),
                          "Native function must fit a vtable slot");
            uintptr_t &entry = checkedAt(view, slot);
            __builtin_memcpy(static_cast<void *>(&entry),
                             static_cast<const void *>(&function),
                             sizeof(entry));
        }
    } // namespace

    static IOReturn close(const IOUserClient *self, bool died)
    {
        auto *state = context(self);
        if ((state == nullptr) ||
            (__atomic_exchange_n(&state->closed, 1U, __ATOMIC_ACQ_REL) != 0U))
        {
            return kIOReturnSuccess;
        }
        return died ? state->implementation->clientDied()
                    : state->implementation->clientClose();
    }

    static IOReturn clientClose(IOUserClient *self)
    {
        const auto result = close(self, false);
        if (!self->isInactive())
        {
            self->terminate();
        }
        return result;
    }

    static IOReturn clientDied(IOUserClient *self)
    {
        const auto result = close(self, true);
        if (!self->isInactive())
        {
            self->terminate();
        }
        return result;
    }

    static bool start(IOUserClient *self, IOService *provider)
    {
        return self->IOUserClient::start(provider);
    }

    static void stop(IOUserClient *self, IOService *provider)
    {
        close(self, false);
        self->IOUserClient::stop(provider);
    }

    static bool init(IOUserClient *self, task_t task, void *token,
                     uint32_t type, OSDictionary *properties)
    {
        return self->IOUserClient::initWithTask(task, token, type, properties);
    }

    static void destruct(IOUserClient *self)
    {
        const auto profile = context(self)->profile;
        native<void (*)(IOUserClient *)>(profileFor(profile).destructor)(self);
    }

    static void deleteObject(IOUserClient *self)
    {
        destruct(self);
        IOFree(self, kClientWrapperBytes);
    }

    static void freeObject(IOUserClient *self)
    {
        auto *state = context(self);
        close(self, false);
        native<void (*)(IOUserClient *)>(profileFor(state->profile).free)(self);
        state->implementation->release();
        IOFree(state, sizeof(*state));
    }

    static IOUserClient *activeImplementation(const IOUserClient *self)
    {
        auto *state = context(self);
        return (state != nullptr) &&
                       (__atomic_load_n(&state->closed, __ATOMIC_ACQUIRE) == 0U)
                   ? state->implementation
                   : nullptr;
    }

    static IOReturn externalMethod(const IOUserClient *self, uint32_t selector,
                                   IOExternalMethodArguments *arguments,
                                   IOExternalMethodDispatch *dispatch,
                                   OSObject *target, void *reference)
    {
        auto *implementation = activeImplementation(self);
        return (implementation != nullptr)
                   ? implementation->externalMethod(
                         selector, arguments, dispatch,
                         target == self ? implementation : target, reference)
                   : kIOReturnNotOpen;
    }

    static IOReturn clientMemory(const IOUserClient *self, uint32_t type,
                                 IOOptionBits *options,
                                 IOMemoryDescriptor **memory)
    {
        auto *implementation = activeImplementation(self);
        return (implementation != nullptr)
                   ? implementation->clientMemoryForType(type, options, memory)
                   : kIOReturnNotOpen;
    }

    static IOReturn notification64(const IOUserClient *self, mach_port_t port,
                                   uint32_t type, uint64_t reference)
    {
        auto *implementation = activeImplementation(self);
        return (implementation != nullptr)
                   ? implementation->registerNotificationPort(port, type,
                                                              reference)
                   : kIOReturnNotOpen;
    }

    static IOReturn notification32(const IOUserClient *self, mach_port_t port,
                                   uint32_t type, uint32_t reference)
    {
        auto *implementation = activeImplementation(self);
        return (implementation != nullptr)
                   ? implementation->registerNotificationPort(port, type,
                                                              reference)
                   : kIOReturnNotOpen;
    }

    static IOService *getService(const IOUserClient *self)
    {
        return context(self)->implementation->getService();
    }

    bool prepareNativeUserClients()
    {
        if (dispatchState().prepared)
        {
            return true;
        }
        if (nativeRuntimeProfileState().system == nullptr)
        {
            return false;
        }
        for (uint32_t i = 0U; i < kClientProfileCount; ++i)
        {
            const auto profile = profileFor(i);
            if (profile.slots != kNativeClientSlots ||
                profile.constructor >= nativeImportCount ||
                profile.destructor >= nativeImportCount ||
                profile.free >= nativeImportCount ||
                profile.meta >= nativeImportCount ||
                profile.vtable >= nativeImportCount ||
                native<const OSMetaClass *>(profile.meta)->getClassSize() !=
                    kClientContextOffset)
            {
                return false;
            }
            auto &view = checkedAt(dispatchState().views, i);
            memcpy(static_cast<void *>(&view[0U]),
                   native<const uintptr_t *>(profile.vtable), sizeof(view));
            setMethod(view, kVtableDestructorSlot, &destruct);
            setMethod(view, kVtableDeletingDestructorSlot, &deleteObject);
            setMethod(view, kFreeSlot, &freeObject);
            setMethod(view, kStartSlot, &start);
            setMethod(view, kStopSlot, &stop);
            setMethod(view, kExternalMethodSlot, &externalMethod);
            setMethod(view, kNotify64Slot, &notification64);
            setMethod(view, kInitSlot, &init);
            setMethod(view, kCloseSlot, &clientClose);
            setMethod(view, kDiedSlot, &clientDied);
            setMethod(view, kServiceSlot, &getService);
            setMethod(view, kNotify32Slot, &notification32);
            setMethod(view, kMemorySlot, &clientMemory);
        }
        dispatchState().prepared = true;
        return true;
    }

    IOReturn wrapNativeUserClient(IOReturn status, task_t task, void *token,
                                  uint32_t type, OSDictionary *properties,
                                  IOUserClient **result)
    {
        if (status != kIOReturnSuccess || (result == nullptr) ||
            ((*result) == nullptr))
        {
            return status;
        }
        auto *implementation = *result;
        uint32_t profile = 0U;
        if (implementation->metaCast("ATH80211UserClient") != nullptr)
        {
            profile = 0;
        }
        else if (implementation->metaCast("SB80211AsyncEventUserClient") !=
                 nullptr)
        {
            profile = 1;
        }
        else
        {
            return status;
        }
        *result = nullptr;
        auto *state =
            dispatchState().prepared
                ? static_cast<ClientContext *>(IOMalloc(sizeof(ClientContext)))
                : nullptr;
        auto *front =
            (state != nullptr)
                ? static_cast<IOUserClient *>(IOMalloc(kClientWrapperBytes))
                : nullptr;
        if (front == nullptr)
        {
            if (state != nullptr)
            {
                IOFree(state, sizeof(*state));
            }
            implementation->clientClose();
            implementation->release();
            return dispatchState().prepared ? kIOReturnNoMemory
                                            : kIOReturnNotReady;
        }
        *state = {implementation, profile, 0};
        memset(static_cast<void *>(front), 0, kClientWrapperBytes);
        const auto spec = profileFor(profile);
        const auto *meta = native<const OSMetaClass *>(spec.meta);
        native<void (*)(IOUserClient *, const OSMetaClass *)>(spec.constructor)(
            front, meta);
        setContext(front, state);
        auto &view = checkedAt(dispatchState().views, profile);
        const uintptr_t *const start = &checkedAt(view, kVtableHeaderSlots);
        __builtin_memcpy(static_cast<void *>(front),
                         static_cast<const void *>(&start), sizeof(start));
        meta->instanceConstructed();
        if (!init(front, task, token, type, properties))
        {
            front->release();
            return kIOReturnError;
        }
        front->setProperty("IOUserClientDefaultLocking", kOSBooleanTrue);
        if (front->attach(implementation))
        {
            if (front->start(implementation))
            {
                *result = front;
                return kIOReturnSuccess;
            }
            front->detach(implementation);
        }
        front->release();
        return kIOReturnError;
    }

} // namespace ath
