// SPDX-License-Identifier: AGPL-3.0-only
#ifndef SIMPLEATH_NATIVE_DIAGNOSTICS_HPP
#define SIMPLEATH_NATIVE_DIAGNOSTICS_HPP
#include "DiagnosticPolicy.hpp"
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSData.h>
#include <libkern/c++/OSString.h>
#include <pexpert/pexpert.h>

namespace simpleath
{
    // Read exported boot metadata only; no EFI mount, filesystem plist
    // dependency or wait for an NVRAM provider. Missing data means normal logs.
    inline DiagnosticSelection readNativeDiagnostics()
    {
        int value = 0;
        if (PE_parse_boot_argn("simpleathdbg", &value, sizeof(value)) != 0)
        {
            return selectDiagnostics(value == 1 ? DiagnosticOverride::Detailed
                                                : DiagnosticOverride::Normal,
                                     nullptr, 0);
        }
        if (PE_parse_boot_argn("-simpleathdbg", &value, sizeof(value)) != 0)
        {
            return selectDiagnostics(DiagnosticOverride::Detailed, nullptr, 0);
        }
        auto const *options = IORegistryEntry::fromPath("/options", gIODTPlane);
        if (options == nullptr)
        {
            return {false, DiagnosticOrigin::Default};
        }
        OSObject const *property = options->copyProperty(
            "4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102:opencore-version");
        options->release();
        DiagnosticSelection selected {false, DiagnosticOrigin::Default};
        if (const auto *data = OSDynamicCast(OSData, property))
        {
            {
                selected = selectDiagnostics(
                    DiagnosticOverride::Automatic,
                    static_cast<const uint8_t *>(data->getBytesNoCopy()),
                    data->getLength());
            }
        }
        else if (const auto *text = OSDynamicCast(OSString, property))
        {
            const auto *string = text->getCStringNoCopy();
            const uint8_t *bytes = nullptr;
            using BytePointer = const uint8_t *;
            using CharacterPointer = const char *;
            static_assert(sizeof(BytePointer) == sizeof(CharacterPointer),
                          "native pointer width");
            __builtin_memcpy(static_cast<void *>(&bytes),
                             static_cast<const void *>(&string),
                             sizeof(BytePointer));
            selected = selectDiagnostics(DiagnosticOverride::Automatic, bytes,
                                         text->getLength());
        }
        if (property != nullptr)
        {
            property->release();
        }
        return selected;
    }

    inline void publishNativeDiagnostics(IOService *owner,
                                         const DiagnosticSelection &selection)
    {
        owner->setProperty("SimpleATHDiagnosticsDetailed", selection.detailed);
        const char *origin = "Default";
        if (selection.origin == DiagnosticOrigin::BootArgument)
        {
            origin = "BootArgument";
        }
        else if (selection.origin == DiagnosticOrigin::OpenCoreDebug)
        {
            origin = "OpenCoreDebug";
        }
        owner->setProperty("SimpleATHDiagnosticsSource", origin);
    }
} // namespace simpleath
#endif
