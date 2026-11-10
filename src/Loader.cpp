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
#include <mach/i386/boolean.h>
#include <mach/i386/kern_return.h>
#include <mach/i386/vm_types.h>
#include <mach/kern_return.h>
#include <mach/kmod.h>
#include <mach/vm_prot.h>
#include <stdint.h>
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

        struct StringProperty
        {
                const char *key;
                const char *value;
        };

        // All binary Mach-O access is validated against the mapped descriptor
        // before copying bytes. No typed object is manufactured by aliasing
        // an executable image's raw storage.
        template <typename T> T *pointerFromAddress(uintptr_t address)
        {
            static_assert(sizeof(T *) == sizeof(uintptr_t),
                          "native mapped addresses must fit a pointer");
            T *pointer = nullptr;
            __builtin_memcpy(static_cast<void *>(&pointer), &address,
                             sizeof(pointer));
            return pointer;
        }

        uintptr_t pointerBits(const void *pointer)
        {
            static_assert(sizeof(uintptr_t) == sizeof(pointer),
                          "native pointer representation must fit uintptr_t");
            uintptr_t address = 0;
            __builtin_memcpy(&address, static_cast<const void *>(&pointer),
                             sizeof(address));
            return address;
        }

        void *mappedAt(const LinkedImage &image, size_t offset, size_t length)
        {
            if (image.payload == nullptr || image.memory == nullptr ||
                offset > image.payload->mappedSize ||
                length > image.payload->mappedSize - offset)
            {
                return nullptr;
            }
            const uintptr_t base = pointerBits(image.memory);
            if (offset > UINTPTR_MAX - base)
            {
                return nullptr;
            }
            return pointerFromAddress<void>(base + offset);
        }

        template <typename T>
        bool readMapped(const LinkedImage &image, size_t offset, T &out)
        {
            const void *source = mappedAt(image, offset, sizeof(T));
            if (source == nullptr)
            {
                return false;
            }
            __builtin_memcpy(&out, source, sizeof(out));
            return true;
        }

        template <typename T>
        bool writeMapped(const LinkedImage &image, size_t offset,
                         const T &value)
        {
            void *destination = mappedAt(image, offset, sizeof(T));
            if (destination == nullptr)
            {
                return false;
            }
            __builtin_memcpy(destination, &value, sizeof(value));
            return true;
        }

        // The generated descriptor array has exactly three elements. A
        // retained native profile may select only its two AirPort variants.
        const Payload *selectedPayload(uint32_t index)
        {
            if (index == 0U)
            {
                return &payloads[0];
            }
            if (nativeSystem == nullptr)
            {
                return nullptr;
            }
            switch (nativeSystem->airPortPayloadIndex)
            {
                case 1U:
                    return &payloads[1];
                case 2U:
                    return &payloads[2];
                default:
                    return nullptr;
            }
        }

        const char *nativeImportName(uint32_t index)
        {
            if (index >= nativeImportCount)
            {
                return nullptr;
            }
            return nativeImportNames[index];
        }

        bool readNativeImport(uint32_t index, uintptr_t &value)
        {
            if (index >= nativeImportCount)
            {
                return false;
            }
            const uintptr_t start = pointerBits(&athNativeImports[0]);
            const size_t offset = static_cast<size_t>(index) * sizeof(value);
            if (offset > UINTPTR_MAX - start)
            {
                return false;
            }
            const void *source = pointerFromAddress<void>(start + offset);
            __builtin_memcpy(&value, source, sizeof(value));
            return true;
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
        const auto *number = OSNumber::withNumber(value, kNumberBits);
        if (number == nullptr)
        {
            return false;
        }
        auto const result = dictionary->setObject(key, number);
        number->release();
        return result;
    }

    static bool setString(OSDictionary *dictionary,
                          const StringProperty &property)
    {
        const auto *string = OSString::withCString(property.value);
        if (string == nullptr)
        {
            return false;
        }
        auto const result = dictionary->setObject(property.key, string);
        string->release();
        return result;
    }

    namespace
    {
        struct SegmentValidationLocation
        {
                size_t cursor;
                uint64_t delta;
        };
    } // namespace

    static bool
    validateSectionAddresses(const LinkedImage &image,
                             const segment_command_64 &segment,
                             const SegmentValidationLocation &location)
    {
        for (uint32_t sectionIndex = 0; sectionIndex < segment.nsects;
             ++sectionIndex)
        {
            section_64 section {};
            const size_t sectionOffset =
                location.cursor + sizeof(segment) +
                (static_cast<size_t>(sectionIndex) * sizeof(section));
            if (!readMapped(image, sectionOffset, section) ||
                section.addr > image.payload->mappedSize ||
                section.addr > UINT64_MAX - location.delta)
            {
                return false;
            }
        }
        return true;
    }

    static bool
    validateSegmentCommand(const LinkedImage &image,
                           const load_command &command,
                           const SegmentValidationLocation &location)
    {
        if (command.cmdsize < sizeof(segment_command_64))
        {
            return false;
        }
        segment_command_64 segment {};
        if (!readMapped(image, location.cursor, segment))
        {
            return false;
        }
        const auto &payload = *image.payload;
        if (segment.nsects >
                (command.cmdsize - sizeof(segment)) / sizeof(section_64) ||
            segment.vmaddr > payload.mappedSize ||
            segment.vmsize > payload.mappedSize - segment.vmaddr ||
            segment.vmaddr > UINT64_MAX - location.delta ||
            segment.vmsize > UINT64_MAX - (segment.vmaddr + location.delta))
        {
            return false;
        }
        return validateSectionAddresses(image, segment, location);
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
        if (!readMapped(image, 0U, header))
        {
            return false;
        }
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
            if (!readMapped(image, cursor, command))
            {
                return false;
            }
            if (command.cmdsize < sizeof(command) ||
                command.cmdsize > remaining ||
                (command.cmdsize % sizeof(uint64_t)) != 0U)
            {
                return false;
            }
            if (command.cmd == LC_SEGMENT_64 &&
                !validateSegmentCommand(
                    image, command, SegmentValidationLocation {cursor, delta}))
            {
                return false;
            }
            cursor += command.cmdsize;
            remaining -= command.cmdsize;
        }
        return remaining == 0U;
    }

    // Each command was checked against the mapped image before this stage.
    // Mutate exactly one structured Mach-O record at a time through bounded
    // byte copies; a raw byte image does not contain C++ objects of these
    // kernel-private record types.
    static bool rebaseImageCommands(const LinkedImage &image)
    {
        mach_header_64 header {};
        if (!readMapped(image, 0U, header))
        {
            return false;
        }
        const uint64_t delta = image.address - vm_kernel_slide;
        size_t cursor = sizeof(header);
        for (uint32_t i = 0; i < header.ncmds; ++i)
        {
            load_command command {};
            if (!readMapped(image, cursor, command))
            {
                return false;
            }
            if (command.cmd == LC_SEGMENT_64)
            {
                segment_command_64 segment {};
                if (!readMapped(image, cursor, segment))
                {
                    return false;
                }
                const size_t sectionsBase = cursor + sizeof(segment);
                for (uint32_t j = 0; j < segment.nsects; ++j)
                {
                    section_64 section {};
                    const size_t at = sectionsBase + (static_cast<size_t>(j) *
                                                      sizeof(section));
                    if (!readMapped(image, at, section))
                    {
                        return false;
                    }
                    section.addr += delta;
                    if (!writeMapped(image, at, section))
                    {
                        return false;
                    }
                }
                segment.vmaddr += delta;
                if (!writeMapped(image, cursor, segment))
                {
                    return false;
                }
            }
            cursor += command.cmdsize;
        }
        return true;
    }

    static bool wireLinkEdit(const LinkedImage &image, kmod_info_t *kmod,
                             OSReturn &result)
    {
        mach_header_64 header {};
        if (!readMapped(image, 0U, header))
        {
            return false;
        }
        size_t cursor = sizeof(header);
        for (uint32_t i = 0; i < header.ncmds; ++i)
        {
            load_command command {};
            if (!readMapped(image, cursor, command))
            {
                return false;
            }
            if (command.cmd == LC_SEGMENT_64)
            {
                segment_command_64 segment {};
                if (!readMapped(image, cursor, segment))
                {
                    return false;
                }
                if (memcmp(&segment.segname[0], "__LINKEDIT",
                           sizeof("__LINKEDIT")) == 0)
                {
                    result = vm_map_wire(kext_get_vm_map(kmod), segment.vmaddr,
                                         segment.vmaddr + segment.vmsize,
                                         VM_PROT_READ, 0);
                    if (result != KERN_SUCCESS)
                    {
                        return false;
                    }
                }
            }
            cursor += command.cmdsize;
        }
        return true;
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
        const auto *object = OSUnserializeXML(p.plist);
        auto *dictionary = OSDynamicCast(OSDictionary, object);
        if (dictionary == nullptr)
        {
            if (object != nullptr)
            {
                object->release();
            }
            return false;
        }
        char path[kPrelinkPathCapacity] {};
        const size_t rootBytes =
            strlcpy(&path[0], "/Library/Extensions/SimpleATH.kext/Embedded/",
                    sizeof(path));
        const size_t pathBytes = strlcat(&path[0], p.identifier, sizeof(path));
        const auto slide = PE_get_kc_slide(kKcKindUnknown);
        if (rootBytes >= sizeof(path) || pathBytes >= sizeof(path) ||
            slide > image.address)
        {
            dictionary->release();
            return false;
        }
        kmod_info_t updatedKmod {};
        if (!readMapped(image, p.kmodOffset, updatedKmod))
        {
            dictionary->release();
            return false;
        }
        updatedKmod.next = nullptr;
        updatedKmod.id = 0;
        updatedKmod.reference_count = 0;
        updatedKmod.reference_list = nullptr;
        updatedKmod.address = 0;
        updatedKmod.size = p.mappedSize;
        updatedKmod.hdr_size = 0;
        if (!writeMapped(image, p.kmodOffset, updatedKmod))
        {
            dictionary->release();
            return false;
        }
        auto *kmod = static_cast<kmod_info_t *>(
            mappedAt(image, p.kmodOffset, sizeof(updatedKmod)));
        if (kmod == nullptr)
        {
            dictionary->release();
            return false;
        }
        bool const valid =
            setString(dictionary,
                      StringProperty {
                          "_PrelinkBundlePath",
                          &path[0],
                      }) &&
            setString(dictionary,
                      StringProperty {
                          "_PrelinkExecutableRelativePath",
                          "Contents/MacOS/Embedded",
                      }) &&
            setNumber(dictionary, "_PrelinkExecutableLoadAddr",
                      image.address - slide) &&
            setNumber(dictionary, "_PrelinkExecutableSize", p.mappedSize) &&
            setNumber(dictionary, "_PrelinkKmodInfo",
                      pointerBits(kmod) - slide);
        if (!valid)
        {
            dictionary->release();
            return false;
        }
        if (!rebaseImageCommands(image))
        {
            dictionary->release();
            return false;
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
        if (!wireLinkEdit(image, kmod, result))
        {
            loaderState().lastError = result;
            return false;
        }
        SYSLOG("loader", "registered %s, %u bytes", p.identifier, p.mappedSize);
        return true;
    }

    static bool validateEmbeddedPrerequisites()
    {
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
        for (const auto index : selected)
        {
            const Payload *payload = selectedPayload(index);
            if (payload == nullptr || payload->identifier == nullptr)
            {
                return fail("InvalidNativePayloadIndex", "SimpleATH", index);
            }
            const auto *existing = athLookupKext(payload->identifier);
            if (existing != nullptr)
            {
                existing->release();
                return fail("ConflictingModule", payload->identifier);
            }
        }
        for (uint32_t i = 0; i < nativeVtableGuardCount; ++i)
        {
            const auto &guard = nativeVtableGuards[i];
            uintptr_t parent = 0;
            uintptr_t expected = 0;
            if (!readNativeImport(guard.parent, parent) ||
                !readNativeImport(guard.method, expected))
            {
                return fail("InvalidVtableGuard", "SimpleATH", i);
            }
            if (guard.offset > UINTPTR_MAX - parent)
            {
                return fail("InvalidVtableGuard", "SimpleATH", i);
            }
            uintptr_t actual = 0;
            const void *entry = pointerFromAddress<void>(parent + guard.offset);
            __builtin_memcpy(&actual, entry, sizeof(actual));
            if (actual != expected)
            {
                return fail("NativeVtableMismatch",
                            nativeImportName(guard.parent), guard.offset);
            }
        }
        return true;
    }

    static bool mapEmbeddedImages()
    {
        loaderState().status = "Mapping";
        for (const auto index : selected)
        {
            auto &image = selectedImage(index);
            image.payload = selectedPayload(index);
            if (image.payload == nullptr)
            {
                return fail("InvalidNativePayloadIndex", "SimpleATH", index);
            }
            vm_offset_t address = 0;
            const auto result =
                kext_alloc(&address, image.payload->mappedSize, 0);
            if (result != KERN_SUCCESS)
            {
                return fail("AllocationFailed", image.payload->identifier,
                            result);
            }
            image.address = address;
            image.memory = pointerFromAddress<uint8_t>(address);
            image.editable = true;
            if (!restorePayload(image))
            {
                return fail("PayloadRestorationFailed",
                            image.payload->identifier);
            }
        }
        return true;
    }

    static bool relocateEmbeddedImages()
    {
        loaderState().status = "Linking";
        for (auto const index : selected)
        {
            if (!relocateImage(selectedImage(index), &loaderState().images[0],
                               2, athNativeImports, nativeImportCount,
                               athCompatibilityImports,
                               compatibilityImportCount))
            {
                return fail("LinkFailed",
                            selectedImage(index).payload->identifier);
            }
        }
        return true;
    }

    static bool prepareNativeBridges()
    {
        Bridge::initialize();
        loaderState().status = "Patching";
        if (!prepareNativeSkywalk(&loaderState().images[0], 2))
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
        return true;
    }

    static bool registerEmbeddedImages()
    {
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
        return true;
    }

    bool preparePayloads()
    {
        if (loaderState().prepared)
        {
            return true;
        }
        if (!validateEmbeddedPrerequisites() || !mapEmbeddedImages() ||
            !relocateEmbeddedImages() || !prepareNativeBridges() ||
            !registerEmbeddedImages())
        {
            return false;
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
        // Produce the exact 8-nibble legacy error property directly, with
        // no dynamic indexing into a fixed-size stack array.
        constexpr unsigned kHexMask = 0x0FU;
        const auto hexDigit = [](unsigned value) -> char
        {
            constexpr unsigned kDecimalDigits = 10U;
            const unsigned nibble = value & kHexMask;
            return nibble < kDecimalDigits
                       ? static_cast<char>('0' + nibble)
                       : static_cast<char>('a' + nibble - kDecimalDigits);
        };
        const uint32_t code = loaderState().lastError;
        constexpr unsigned kShift28 = 28U;
        constexpr unsigned kShift24 = 24U;
        constexpr unsigned kShift20 = 20U;
        constexpr unsigned kShift16 = 16U;
        constexpr unsigned kShift12 = 12U;
        constexpr unsigned kShift8 = 8U;
        constexpr unsigned kShift4 = 4U;
        const char error[kErrorHexCapacity] {
            '0',
            'x',
            hexDigit(code >> kShift28),
            hexDigit(code >> kShift24),
            hexDigit(code >> kShift20),
            hexDigit(code >> kShift16),
            hexDigit(code >> kShift12),
            hexDigit(code >> kShift8),
            hexDigit(code >> kShift4),
            hexDigit(code),
            '\0',
        };
        service->setProperty("LoaderErrorHex", &error[0]);
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
