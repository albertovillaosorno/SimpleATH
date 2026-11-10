//
//  Loader.cpp
//  SimpleATH
//
//  Created by laobamac on 2026/11/1.
//  Copyright © 2026 laobamac. All rights reserved.
//

#include "Loader.hpp"
#include "Bridge.hpp"
#include "NativeProfile.hpp"
#include "NativeSkywalk.hpp"
#include "NativeUserClient.hpp"
#include "Patcher.hpp"
#include "Payload.hpp"
#include <IOKit/IOCatalogue.h>
#include <libkern/OSReturn.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSNumber.h>
#include <libkern/c++/OSUnserialize.h>
#include <mach-o/loader.h>
#include <mach/kern_return.h>
#include <mach/kmod.h>
#include <mach/machine/boolean.h>
#include <mach/machine/vm_types.h>
#include <mach/vm_prot.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern "C" kern_return_t kext_alloc(vm_offset_t *, vm_size_t, boolean_t);
extern "C" void kext_free(vm_offset_t, vm_size_t);
extern "C" uintptr_t vm_kernel_slide;
extern "C" uintptr_t PE_get_kc_slide(int);
extern "C" void *kext_get_vm_map(kmod_info_t *);
extern "C" kern_return_t vm_map_wire(void *, uintptr_t, uintptr_t, vm_prot_t,
                                     boolean_t);
extern "C" OSObject *
athLookupKext(const char *) asm("__ZN6OSKext24lookupKextWithIdentifierEPKc");
extern "C" OSObject *athRegisterKext(OSDictionary *, bool, int) asm(
    "__ZN6OSKext21withPrelinkedInfoDictEP12OSDictionaryb7kc_kind");
extern "C" OSReturn athProtectKext(OSObject *, bool,
                                   bool) asm("__ZN6OSKext15setVMAttributesEbb");
extern "C" OSReturn
athValidateKextMapping(OSObject *,
                       bool) asm("__ZN6OSKext19validateKextMappingEb");
extern "C" bool
athSetAutounloadEnabled(OSObject *,
                        bool) asm("__ZN6OSKext20setAutounloadEnabledEb");
extern "C" OSReturn athLoadKext(
    const char *, bool, bool, uint8_t, uint8_t,
    OSArray *) asm("__ZN6OSKext22loadKextWithIdentifierEPKcbbhhP7OSArray");

namespace ath
{

    static constexpr int kKcKindUnknown = 0;
    static constexpr uint32_t kMinimumDarwinVersion = 23U;
    static constexpr uint32_t kMaximumDarwinVersion = 25U;
    static constexpr unsigned kNumberBits = 64U;
    static constexpr size_t kPrelinkPathCapacity = 256U;
    static constexpr size_t kErrorHexCapacity = sizeof("0x00000000");
    static constexpr unsigned kPropertyBits = 32U;

    namespace
    {
        // One private lifetime owner for the embedded loader. Mutable state is
        // neither exported nor separately accessible across translation units.
        struct LoaderState
        {
                LinkedImage images[2] {};
                OSObject *modules[2] {};
                const char *status {"NotPrepared"};
                const char *failedModule {""};
                uint32_t lastError {0};
                uint32_t loadedCount {0};
                uint32_t validatedCount {0};
                bool prepared {false};
                bool started {false};
        };

        // This must remain constant-initializable inside the kernel: no
        // dynamic first-use guard, allocations or startup order dependency.
        static_assert(LoaderState {}.status != nullptr,
                      "loader state must be constant-initializable");

        LoaderState &loaderState()
        {
            static LoaderState state {};
            return state;
        }

        // Only two fixed embedded modules are loadable. This accessor keeps
        // runtime indices away from unchecked array subscripts.
        LinkedImage &selectedImage(uint32_t index)
        {
            return index == 0U ? loaderState().images[0]
                               : loaderState().images[1];
        }

        OSObject *&selectedModule(uint32_t index)
        {
            return index == 0U ? loaderState().modules[0]
                               : loaderState().modules[1];
        }
    } // namespace

    static constexpr uint32_t selected[] = {0, 1};

    static bool fail(const char *reason, const char *module, uint32_t error = 0)
    {
        Bridge::disable(reason);
        loaderState().status = reason;
        loaderState().failedModule = module;
        loaderState().lastError = error;
        SYSLOG("loader", "%s: %s (0x%08x)", reason, module, error);
        for (auto &image : loaderState().images)
        {
            if ((image.memory != nullptr) && !image.registered)
            {
                kext_free(image.address, image.payload->mappedSize);
                image.memory = nullptr;
            }
        }
        return false;
    }

    static bool setNumber(OSDictionary *dictionary, const char *key,
                          uint64_t value)
    {
        auto *number = OSNumber::withNumber(value, kNumberBits);
        if (number == nullptr)
        {
            return false;
        }
        auto const result = dictionary->setObject(key, number);
        number->release();
        return result;
    }

    static bool setString(OSDictionary *dictionary, const char *key,
                          const char *value)
    {
        auto *string = OSString::withCString(value);
        if (string == nullptr)
        {
            return false;
        }
        auto const result = dictionary->setObject(key, string);
        string->release();
        return result;
    }

    // The relocated Mach-O image comes from stored payload bytes. Prove that
    // every subsequent in-place load-command and section write remains inside
    // the mapped image before modifying any command or registering a kext.
    static bool validateImageCommands(const LinkedImage &image)
    {
        if (image.payload == nullptr || image.memory == nullptr ||
            image.registered || !image.editable)
        {
            return false;
        }
        const auto &payload = *image.payload;
        if (payload.size < sizeof(mach_header_64) ||
            payload.size > payload.mappedSize ||
            image.address > UINTPTR_MAX - payload.mappedSize ||
            image.address < vm_kernel_slide || payload.identifier == nullptr ||
            payload.plist == nullptr || payload.kmodOffset > payload.size ||
            sizeof(kmod_info_t) > payload.size - payload.kmodOffset ||
            (payload.kmodOffset % alignof(kmod_info_t)) != 0U)
        {
            return false;
        }

        mach_header_64 header {};
        memcpy(&header, image.memory, sizeof(header));
        if (header.magic != MH_MAGIC_64 || header.ncmds == 0U ||
            header.sizeofcmds > payload.size - sizeof(header) ||
            payload.kmodOffset < sizeof(header) + header.sizeofcmds)
        {
            return false;
        }
        const uint64_t delta = image.address - vm_kernel_slide;
        size_t cursor = sizeof(header);
        size_t remaining = header.sizeofcmds;
        for (uint32_t index = 0; index < header.ncmds; ++index)
        {
            if (remaining < sizeof(load_command))
            {
                return false;
            }
            load_command command {};
            memcpy(&command, image.memory + cursor, sizeof(command));
            if (command.cmdsize < sizeof(command) ||
                command.cmdsize > remaining ||
                (command.cmdsize % sizeof(uint64_t)) != 0U)
            {
                return false;
            }
            if (command.cmd == LC_SEGMENT_64)
            {
                if (command.cmdsize < sizeof(segment_command_64))
                {
                    return false;
                }
                segment_command_64 segment {};
                memcpy(&segment, image.memory + cursor, sizeof(segment));
                if (segment.nsects > (command.cmdsize - sizeof(segment)) /
                                         sizeof(section_64) ||
                    segment.vmaddr > payload.mappedSize ||
                    segment.vmsize > payload.mappedSize - segment.vmaddr ||
                    segment.vmaddr > UINT64_MAX - delta ||
                    segment.vmsize > UINT64_MAX - (segment.vmaddr + delta))
                {
                    return false;
                }
                for (uint32_t sectionIndex = 0; sectionIndex < segment.nsects;
                     ++sectionIndex)
                {
                    section_64 section {};
                    memcpy(&section,
                           image.memory + cursor + sizeof(segment) +
                               (static_cast<size_t>(sectionIndex) *
                                sizeof(section)),
                           sizeof(section));
                    if (section.addr > payload.mappedSize ||
                        section.addr > UINT64_MAX - delta)
                    {
                        return false;
                    }
                }
            }
            cursor += command.cmdsize;
            remaining -= command.cmdsize;
        }
        return remaining == 0U;
    }

    static bool registerImage(uint32_t index)
    {
        if (index > 1U)
        {
            return false;
        }
        auto &image = selectedImage(index);
        if (!validateImageCommands(image))
        {
            return false;
        }
        const auto &p = *image.payload;
        auto *object = OSUnserializeXML(p.plist);
        auto *dictionary = OSDynamicCast(OSDictionary, object);
        if (dictionary == nullptr)
        {
            if (object != nullptr)
            {
                object->release();
            }
            return false;
        }
        char path[kPrelinkPathCapacity];
        const int pathBytes = snprintf(
            path, sizeof(path),
            "/Library/Extensions/SimpleATH.kext/Embedded/%s", p.identifier);
        const auto slide = PE_get_kc_slide(kKcKindUnknown);
        if (pathBytes < 0 || static_cast<size_t>(pathBytes) >= sizeof(path) ||
            slide > image.address)
        {
            dictionary->release();
            return false;
        }
        auto *kmod =
            reinterpret_cast<kmod_info_t *>(image.memory + p.kmodOffset);
        kmod->next = nullptr;
        kmod->id = 0;
        kmod->reference_count = 0;
        kmod->reference_list = nullptr;
        kmod->address = 0;
        kmod->size = p.mappedSize;
        kmod->hdr_size = 0;
        bool const valid =
            setString(dictionary, "_PrelinkBundlePath", path) &&
            setString(dictionary, "_PrelinkExecutableRelativePath",
                      "Contents/MacOS/Embedded") &&
            setNumber(dictionary, "_PrelinkExecutableLoadAddr",
                      image.address - slide) &&
            setNumber(dictionary, "_PrelinkExecutableSize", p.mappedSize) &&
            setNumber(dictionary, "_PrelinkKmodInfo",
                      reinterpret_cast<uintptr_t>(kmod) - slide);
        if (!valid)
        {
            dictionary->release();
            return false;
        }
        auto *header = reinterpret_cast<mach_header_64 *>(image.memory);
        auto *command = reinterpret_cast<load_command *>(header + 1);
        for (uint32_t i = 0; i < header->ncmds; ++i)
        {
            if (command->cmd == LC_SEGMENT_64)
            {
                auto *segment = reinterpret_cast<segment_command_64 *>(command);
                segment->vmaddr += image.address - vm_kernel_slide;
                auto *section = reinterpret_cast<section_64 *>(segment + 1);
                for (uint32_t j = 0; j < segment->nsects; ++j)
                {
                    section[j].addr += image.address - vm_kernel_slide;
                }
            }
            command = reinterpret_cast<load_command *>(
                reinterpret_cast<uint8_t *>(command) + command->cmdsize);
        }
        image.registered = true;
        selectedModule(index) =
            athRegisterKext(dictionary, true, kKcKindUnknown);
        dictionary->release();
        if (selectedModule(index) == nullptr)
        {
            return false;
        }
        athSetAutounloadEnabled(selectedModule(index), false);
        image.editable = false;
        auto result = athProtectKext(selectedModule(index), true, false);
        if (result != KERN_SUCCESS)
        {
            loaderState().lastError = result;
            return false;
        }
        command = reinterpret_cast<load_command *>(header + 1);
        for (uint32_t i = 0; i < header->ncmds; ++i)
        {
            if (command->cmd == LC_SEGMENT_64)
            {
                auto *segment = reinterpret_cast<segment_command_64 *>(command);
                if (memcmp(segment->segname, "__LINKEDIT",
                           sizeof("__LINKEDIT")) == 0)
                {
                    result = vm_map_wire(kext_get_vm_map(kmod), segment->vmaddr,
                                         segment->vmaddr + segment->vmsize,
                                         VM_PROT_READ, 0);
                    if (result != KERN_SUCCESS)
                    {
                        loaderState().lastError = result;
                        return false;
                    }
                }
            }
            command = reinterpret_cast<load_command *>(
                reinterpret_cast<uint8_t *>(command) + command->cmdsize);
        }
        SYSLOG("loader", "registered %s, %u bytes", p.identifier, p.mappedSize);
        return true;
    }

    bool preparePayloads()
    {
        if (loaderState().prepared)
        {
            return true;
        }
        auto const kernel = getKernelVersion();
        if (kernel < kMinimumDarwinVersion || kernel > kMaximumDarwinVersion)
        {
            return fail("UnsupportedKernel", "SimpleATH", kernel);
        }
        if (!validateNativeSkywalk())
        {
            return fail("UnsupportedNativeSkywalk",
                        "com.apple.iokit.IOSkywalkFamily");
        }
        if (!prepareNativeUserClients())
        {
            return fail("UnsupportedNativeWireless",
                        "com.apple.iokit.IO80211Family");
        }
        for (auto const index : selected)
        {
            const auto &payload =
                payloads[(index != 0U) ? nativeSystem->airPortPayloadIndex : 0];
            auto *existing = athLookupKext(payload.identifier);
            if (existing != nullptr)
            {
                existing->release();
                return fail("ConflictingModule", payload.identifier);
            }
        }
        for (uint32_t i = 0; i < nativeVtableGuardCount; ++i)
        {
            const auto &guard = nativeVtableGuards[i];
            if (guard.parent >= nativeImportCount ||
                guard.method >= nativeImportCount)
            {
                return fail("InvalidVtableGuard", "SimpleATH", i);
            }
            uintptr_t method = 0;
            memcpy(&method,
                   reinterpret_cast<void *>(athNativeImports[guard.parent] +
                                            guard.offset),
                   sizeof(method));
            if (method != athNativeImports[guard.method])
            {
                return fail("NativeVtableMismatch",
                            nativeImportNames[guard.parent], guard.offset);
            }
        }
        loaderState().status = "Mapping";
        for (auto const index : selected)
        {
            auto &image = selectedImage(index);
            image.payload =
                &payloads[(index != 0U) ? nativeSystem->airPortPayloadIndex
                                        : 0];
            vm_offset_t address = 0;
            auto const result =
                kext_alloc(&address, image.payload->mappedSize, 0);
            if (result != KERN_SUCCESS)
            {
                return fail("AllocationFailed", image.payload->identifier,
                            result);
            }
            image.address = address;
            image.memory = reinterpret_cast<uint8_t *>(address);
            image.editable = true;
            if (!restorePayload(image))
            {
                return fail("PayloadRestorationFailed",
                            image.payload->identifier);
            }
        }
        loaderState().status = "Linking";
        for (auto const index : selected)
        {
            if (!relocateImage(selectedImage(index), loaderState().images, 2,
                               athNativeImports, nativeImportCount,
                               athCompatibilityImports,
                               compatibilityImportCount))
            {
                return fail("LinkFailed",
                            selectedImage(index).payload->identifier);
            }
        }
        Bridge::initialize();
        loaderState().status = "Patching";
        if (!prepareNativeSkywalk(loaderState().images, 2))
        {
            return fail("NativeAdapterFailed", "SimpleATH");
        }
        Bridge::enableNativeSkywalk();
        if (!Bridge::prepareImage(loaderState().images[0], 0) ||
            !Bridge::prepareImage(loaderState().images[1], 1) ||
            !Bridge::ready())
        {
            return fail("BridgeFailed", "SimpleATH");
        }
        loaderState().status = "Registering";
        for (auto const index : selected)
        {
            if (!registerImage(index))
            {
                return fail("RegistrationFailed",
                            selectedImage(index).payload->identifier,
                            loaderState().lastError);
            }
        }
        loaderState().prepared = true;
        loaderState().status = "Prepared";
        return true;
    }

    bool startPayloads()
    {
        if (loaderState().started)
        {
            return true;
        }
        if (!loaderState().prepared)
        {
            return false;
        }
        loaderState().status = "Loading";
        for (auto const index : selected)
        {
            auto const result =
                athLoadKext(selectedImage(index).payload->identifier, false,
                            true, 2, 2, nullptr);
            if (result != KERN_SUCCESS)
            {
                return fail("LoadFailed",
                            selectedImage(index).payload->identifier, result);
            }
            ++loaderState().loadedCount;
        }
        loaderState().status = "ValidatingMappings";
        for (auto const index : selected)
        {
            auto const result =
                athValidateKextMapping(selectedModule(index), true);
            if (result != KERN_SUCCESS)
            {
                return fail("MappingValidationFailed",
                            selectedImage(index).payload->identifier, result);
            }
            ++loaderState().validatedCount;
        }
        loaderState().status = "Starting";
        for (auto const index : selected)
        {
            auto const result =
                athLoadKext(selectedImage(index).payload->identifier, false,
                            true, 0, 2, nullptr);
            if (result != KERN_SUCCESS)
            {
                return fail("StartFailed",
                            selectedImage(index).payload->identifier, result);
            }
        }
        loaderState().status = "Matching";
        for (auto const index : selected)
        {
            auto const result =
                athLoadKext(selectedImage(index).payload->identifier, false,
                            true, 0, 0, nullptr);
            if (result != KERN_SUCCESS)
            {
                return fail("MatchingFailed",
                            selectedImage(index).payload->identifier, result);
            }
            gIOCatalogue->moduleHasLoaded(
                selectedImage(index).payload->identifier);
        }
        loaderState().started = true;
        loaderState().status = "StartedAwaitingHardware";
        SYSLOG("loader", "embedded stack started on Darwin %u",
               getKernelVersion());
        return true;
    }

    void publishLoader(IOService *service)
    {
        service->setProperty("Status", loaderState().status);
        service->setProperty("LoaderStatus", loaderState().status);
        service->setProperty("LoaderFailedModule", loaderState().failedModule);
        service->setProperty("LoaderError", loaderState().lastError,
                             kPropertyBits);
        char error[kErrorHexCapacity];
        snprintf(error, sizeof(error), "0x%08x", loaderState().lastError);
        service->setProperty("LoaderErrorHex", error);
        service->setProperty("LoaderKCType", "KCKindUnknown");
        service->setProperty("DriverLoading", "Embedded");
        service->setProperty("ExternalLiluRequired", false);
        service->setProperty("EmbeddedModulesStarted", loaderState().started);
        service->setProperty("EmbeddedModulesLoaded", loaderState().loadedCount,
                             kPropertyBits);
        service->setProperty("EmbeddedMappingsValidated",
                             loaderState().validatedCount, kPropertyBits);
        if (loaderState().images[1].payload != nullptr)
        {
            service->setProperty("AirPortSHA256",
                                 loaderState().images[1].payload->sha256);
        }
        publishNativeSkywalk(service);
    }

} // namespace ath
