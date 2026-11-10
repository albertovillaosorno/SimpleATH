#include "Ar9565NativePci.hpp"
#include "Ar9565PciSession.hpp"
#include "hardware/Ar9565Core.hpp"
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/IOService.h>
#include <IOKit/IOTypes.h>
#include <IOKit/pci/IOPCIDevice.h>
#include <IOKit/pci/IOPCIFamilyDefinitions.h>
#include <libkern/OSTypes.h>
#include <stddef.h>
#include <stdint.h>
#ifndef __x86_64__
#error The native PCI backend requires the Intel ABI
#endif
#include <libkern/OSByteOrder.h>

namespace simpleath
{
    namespace
    {
        constexpr uint16_t kPciCommandOffset = 0x04U;
        constexpr uint16_t kPciBar0Offset = 0x10U;
        constexpr uint16_t kPciBar0HighOffset = 0x14U;
        constexpr uint16_t kPciConfigMaximum = 0xfcU;
        constexpr uint32_t kInvalidRegisterValue = UINT32_MAX;
        constexpr uint32_t kCommandMemoryDecode = 0x0002U;
        constexpr uint32_t kCommandBusMaster = 0x0004U;
        constexpr uint32_t kCommandMemoryAndMaster =
            kCommandMemoryDecode | kCommandBusMaster;
        constexpr uint32_t kBarMemoryTypeMask = 0x09U;
        constexpr uint32_t kBarMemoryAddressMask = 0xfffffff0U;
        constexpr uint8_t kPowerCapabilityMinimum = 0x40U;
        constexpr uint8_t kPowerCapabilityMaximum = 0xf8U;
        constexpr uint16_t kPciPowerStateOffset = 4U;

        uintptr_t pointerAddress(const void *value)
        {
            static_assert(sizeof(uintptr_t) == sizeof(value),
                          "native PCI pointer width must match address width");
            uintptr_t address = 0;
            __builtin_memcpy(&address, static_cast<const void *>(&value),
                             sizeof(value));
            return address;
        }

        template <typename Pointer>
        Pointer pointerFromAddress(uintptr_t address)
        {
            static_assert(sizeof(Pointer) == sizeof(address),
                          "native PCI mapped pointer width must match address");
            Pointer pointer = nullptr;
            __builtin_memcpy(static_cast<void *>(&pointer), &address,
                             sizeof(address));
            return pointer;
        }

        // Check overlap without adding untrusted pointer lengths or wrapping
        // an address-sized integer. A single byte checks an opaque context's
        // known base, not the extent of its caller-owned allocation.
        bool overlapsStorage(const void *first, size_t firstLength,
                             const void *second, size_t secondLength)
        {
            if ((first == nullptr) || (second == nullptr) ||
                (firstLength == 0U) || (secondLength == 0U))
            {
                return false;
            }
            const uintptr_t left = pointerAddress(first);
            const uintptr_t right = pointerAddress(second);
            return left >= right ? left - right < secondLength
                                 : right - left < firstLength;
        }
    } // namespace

    NativePciBackend::NativePciBackend() = default;

    NativePciBackend::~NativePciBackend()
    {
        // Explicit session.stop(), followed by clear(), is required under the
        // owner's lifecycle serialization. Never infer D0 or close an active
        // provider implicitly during object destruction in an unknown context.
        // Provider state cannot be safely restored from a destructor.
        // Preserve incomplete teardown on the still-live registry owner.
        if ((configured_ || claimed_ || (bar_ != nullptr)) &&
            owner_ != nullptr && !owner_->isInactive())
        {
            owner_->setProperty("SimpleATHNativePciTeardownIncomplete", true);
        }
    }

    bool NativePciBackend::configure(IOService *owner, IOPCIDevice *pci,
                                     const NativePciPowerGate &power)
    {
        if (configured_ || claimed_ || (bar_ != nullptr) ||
            (owner_ != nullptr) || (pci_ != nullptr) || (owner == nullptr) ||
            (pci == nullptr) || (power.context == nullptr) ||
            (power.isConfirmedD0 == nullptr) || owner->isInactive() ||
            pci->isInactive() || owner->getProvider() != pci)
        {
            return false;
        }
        owner_ = owner;
        pci_ = pci;
        owner_->retain();
        pci_->retain();
        power_ = power;
        configured_ = true;
        return true;
    }

    PciSessionBackend NativePciBackend::callbacks()
    {
        if (!configured_)
        {
            return {};
        }
        return {
            this,           claim,   release,   inD0,     configRead32,
            commandWrite16, mapBar0, unmapBar0, readBar0,
        };
    }

    bool NativePciBackend::clear()
    {
        if (claimed_ || (bar_ != nullptr) || dmaEnabled_)
        {
            return false;
        }
        configured_ = false;
        power_ = {};
        length_ = 0;
        powerCapability_ = 0;
        if (pci_ != nullptr)
        {
            pci_->release();
            pci_ = nullptr;
        }
        if (owner_ != nullptr)
        {
            owner_->release();
            owner_ = nullptr;
        }
        return true;
    }

    bool NativePciBackend::claim(void *context)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if (!self.configured_ || self.claimed_ || (self.bar_ != nullptr) ||
            self.owner_->isInactive() || self.pci_->isInactive() ||
            self.owner_->getProvider() != self.pci_ ||
            self.pci_->isOpen(nullptr))
        {
            return false;
        }
        // IOPCIDevice's provider open protocol is the ownership operation.
        // A registry match/category is not a claim. Do not seize another
        // client.
        if (!self.pci_->open(self.owner_, 0, nullptr))
        {
            return false;
        }
        if (!self.pci_->isOpen(self.owner_) || self.pci_->isInactive())
        {
            self.pci_->close(self.owner_);
            return false;
        }
        UInt8 capability = 0;
        const UInt32 header = self.pci_->findPCICapability(
            kIOPCICapabilityIDPowerManagement, &capability);
        if ((header == 0U) || header == UINT32_MAX ||
            capability < kPowerCapabilityMinimum ||
            capability > kPowerCapabilityMaximum || ((capability & 3U) != 0U))
        {
            self.pci_->close(self.owner_);
            return false;
        }
        self.powerCapability_ = capability;
        self.claimed_ = true;
        return true;
    }

    void NativePciBackend::release(void *context)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        // PciReadOnlySession revokes its core callbacks before calling here.
        const bool hadClaim = self.claimed_;
        self.claimed_ = false;
        unmapBar0(context);
        if (hadClaim && self.configured_ && self.pci_->isOpen(self.owner_))
        {
            self.pci_->close(self.owner_);
        }
        // configure() references survive until explicit clear(); no driver
        // config or MMIO operation is issued from this release callback.
    }

    bool NativePciBackend::inD0(void *context)
    {
        const auto &self = *static_cast<NativePciBackend *>(context);
        return self.configured_ && self.claimed_ &&
               !self.owner_->isInactive() && !self.pci_->isInactive() &&
               self.owner_->getProvider() == self.pci_ &&
               self.pci_->isOpen(self.owner_) &&
               self.power_.isConfirmedD0(self.power_.context) &&
               (self.powerCapability_ != 0U) &&
               (self.pci_->extendedConfigRead16(self.powerCapability_ +
                                                kPciPowerStateOffset) &
                kPCIPMCSPowerStateMask) == kPCIPMCSPowerStateD0;
    }

    bool NativePciBackend::configRead32(void *context, uint16_t offset,
                                        uint32_t *value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if ((value == nullptr) || ((offset & 3U) != 0U) ||
            offset > kPciConfigMaximum ||
            overlapsStorage(value, sizeof(*value), &self, sizeof(self)) ||
            overlapsStorage(value, sizeof(*value), self.power_.context, 1) ||
            ((self.bar_ != nullptr) &&
             overlapsStorage(value, sizeof(*value),
                             pointerFromAddress<const void *>(
                                 self.bar_->getVirtualAddress()),
                             self.length_)) ||
            !inD0(context))
        {
            return false;
        }
        const uint32_t observed = self.pci_->extendedConfigRead32(offset);
        if (observed == kInvalidRegisterValue)
        {
            return false;
        }
        *value = observed;
        return true;
    }

    bool NativePciBackend::commandWrite16(void *context, uint16_t value)
    {
        uint32_t current = 0;
        if (((value & kCommandBusMaster) != 0U) ||
            !configRead32(context, kPciCommandOffset, &current) ||
            (((static_cast<uint32_t>(static_cast<uint16_t>(current)) ^
               static_cast<uint32_t>(value)) &
              (static_cast<uint32_t>(UINT16_MAX) ^ kCommandMemoryDecode)) !=
             0U) ||
            !inD0(context))
        {
            return false;
        }
        const auto &self = *static_cast<NativePciBackend *>(context);
        // Never write PCI status at 0x06, enable DMA, or change other command
        // bits. The portable session reads command back and retains any restore
        // obligation.
        self.pci_->extendedConfigWrite16(kPciCommandOffset, value);
        return true;
    }

    bool NativePciBackend::mapBar0(void *context, uint32_t *lengthBytes)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if ((lengthBytes == nullptr) ||
            overlapsStorage(lengthBytes, sizeof(*lengthBytes), &self,
                            sizeof(self)) ||
            overlapsStorage(lengthBytes, sizeof(*lengthBytes),
                            self.power_.context, 1) ||
            ((self.bar_ != nullptr) &&
             overlapsStorage(lengthBytes, sizeof(*lengthBytes),
                             pointerFromAddress<const void *>(
                                 self.bar_->getVirtualAddress()),
                             self.length_)))
        {
            return false;
        }
        *lengthBytes = 0;
        if ((self.bar_ != nullptr) || !inD0(context))
        {
            return false;
        }
        uint32_t command = 0;
        uint32_t bar = 0;
        uint32_t upper = 0;
        if (!configRead32(context, kPciCommandOffset, &command) ||
            (command & kCommandMemoryAndMaster) != kCommandMemoryDecode ||
            !configRead32(context, kPciBar0Offset, &bar) ||
            ((bar & kBarMemoryTypeMask) != 0U))
        {
            return false;
        }
        const uint32_t kind = (bar >> 1U) & 3U;
        if (kind != 0 && kind != 2)
        {
            return false;
        }
        if (kind == 2 && !configRead32(context, kPciBar0HighOffset, &upper))
        {
            return false;
        }
        if (((bar & kBarMemoryAddressMask) == 0U) && (upper == 0U))
        {
            return false;
        }
        // Map the PCI family's assigned BAR by CONFIG REGISTER, never array
        // index, raw physical address, an injected registry value, or
        // destructive BAR sizing.
        IOMemoryMap *mapping = self.pci_->mapDeviceMemoryWithRegister(
            kPciBar0Offset, kIOMapInhibitCache);
        if (mapping == nullptr)
        {
            return false;
        }
        const auto length = mapping->getLength();
        const auto address = mapping->getVirtualAddress();
        // The provider supplies a virtual address and length separately.
        // Reject a wrapping window before publishing it or later deriving
        // a register pointer by adding an offset to the mapped base.
        if (!inD0(context) || (address == 0U) || ((address & 3U) != 0U) ||
            length < kRtcStatusRegister + sizeof(uint32_t) ||
            length > UINT32_MAX || length > UINTPTR_MAX - address)
        {
            mapping->release();
            return false;
        }
        self.bar_ = mapping;
        self.length_ = static_cast<uint32_t>(length);
        *lengthBytes = self.length_;
        return true;
    }

    void NativePciBackend::unmapBar0(void *context)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        const IOMemoryMap *const mapping = self.bar_;
        // Revoke the pointer/length before releasing the provider-owned map.
        self.bar_ = nullptr;
        self.length_ = 0;
        if (mapping != nullptr)
        {
            mapping->release();
        }
    }

    bool NativePciBackend::readBar0(void *context, uint32_t offset,
                                    uint32_t *value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if ((value == nullptr) || (self.bar_ == nullptr) ||
            overlapsStorage(value, sizeof(*value), &self, sizeof(self)) ||
            overlapsStorage(value, sizeof(*value), self.power_.context, 1) ||
            overlapsStorage(value, sizeof(*value),
                            pointerFromAddress<const void *>(
                                self.bar_->getVirtualAddress()),
                            self.length_) ||
            !inD0(context) ||
            (offset != kRevisionRegister && offset != kRtcStatusRegister &&
             offset != kEepromStatusRegister) ||
            offset > self.length_ || self.length_ - offset < sizeof(uint32_t))
        {
            return false;
        }
        const auto address = self.bar_->getVirtualAddress();
        // A mapping invalidated or unexpectedly changed after publication
        // must never wrap the address calculation in OSReadLittleInt32.
        if ((address == 0U) || ((address & 3U) != 0U) ||
            self.length_ > UINTPTR_MAX - address)
        {
            return false;
        }
        // The pinned SDK's OSSynchronizeIO is empty on Intel. Use Clang's full
        // hardware/compiler fence around the volatile little-endian MMIO load.
        __sync_synchronize();
        const uint32_t observed = OSReadLittleInt32(
            pointerFromAddress<const volatile void *>(address), offset);
        __sync_synchronize();
        if (observed == kInvalidRegisterValue)
        {
            return false;
        }
        *value = observed;
        return true;
    }

    bool NativePciBackend::setBusMasterGated(bool enabled)
    {
        uint32_t command = 0;
        if ((bar_ == nullptr) || !inD0(this) ||
            !configRead32(this, kPciCommandOffset, &command) ||
            (command & kCommandMemoryDecode) == 0U)
        {
            return false;
        }
        const auto desired =
            static_cast<uint16_t>(enabled ? command | kCommandBusMaster
                                          : command & ~kCommandBusMaster);
        // Do not write PCI status or alter unrelated command bits.
        pci_->extendedConfigWrite16(kPciCommandOffset, desired);
        uint32_t observed = 0;
        if (!configRead32(this, kPciCommandOffset, &observed) ||
            static_cast<uint16_t>(observed) != desired || !inD0(this))
        {
            return false;
        }
        dmaEnabled_ = enabled;
        return true;
    }

    RegisterBus NativePciBackend::activeRegisters()
    {
        if ((bar_ == nullptr) || !inD0(this))
        {
            return {};
        }
        return {this, readActive, writeActive, length_};
    }

    bool NativePciBackend::readActive(void *context, uint32_t offset,
                                      uint32_t *value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if ((value == nullptr) || (self.bar_ == nullptr) || !inD0(context) ||
            ((offset & 3U) != 0U) || offset > self.length_ ||
            self.length_ - offset < sizeof(uint32_t) ||
            overlapsStorage(value, sizeof(*value), &self, sizeof(self)) ||
            overlapsStorage(value, sizeof(*value),
                            pointerFromAddress<const void *>(
                                self.bar_->getVirtualAddress()),
                            self.length_))
        {
            return false;
        }
        const auto address = self.bar_->getVirtualAddress();
        if ((address == 0U) || self.length_ > UINTPTR_MAX - address)
        {
            return false;
        }
        __sync_synchronize();
        const uint32_t observed = OSReadLittleInt32(
            pointerFromAddress<const volatile void *>(address), offset);
        __sync_synchronize();
        if (!inD0(context))
        {
            return false;
        }
        // EEPROM/OTP data can legitimately contain all-one words.
        *value = observed;
        return true;
    }

    bool NativePciBackend::writeActive(void *context, uint32_t offset,
                                       uint32_t value)
    {
        const auto &self = *static_cast<NativePciBackend *>(context);
        uint32_t command = 0;
        if ((self.bar_ == nullptr) ||
            !configRead32(context, kPciCommandOffset, &command) ||
            (command & kCommandMemoryAndMaster) !=
                (self.dmaEnabled_ ? kCommandMemoryAndMaster
                                  : kCommandMemoryDecode) ||
            ((offset & 3U) != 0U) || offset > self.length_ ||
            self.length_ - offset < sizeof(uint32_t))
        {
            return false;
        }
        const auto address = self.bar_->getVirtualAddress();
        if ((address == 0U) || self.length_ > UINTPTR_MAX - address ||
            !inD0(context))
        {
            return false;
        }
        __sync_synchronize();
        OSWriteLittleInt32(pointerFromAddress<volatile void *>(address), offset,
                           value);
        __sync_synchronize();
        // A same-device MMIO read drains posted writes before the reset
        // code starts measuring its pulse or delay. SREV is read-only.
        uint32_t revision = 0;
        return readActive(context, kRevisionRegister, &revision) &&
               revision != UINT32_MAX;
    }

} // namespace simpleath
