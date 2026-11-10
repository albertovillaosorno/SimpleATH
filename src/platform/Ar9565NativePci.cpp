// SPDX-License-Identifier: AGPL-3.0-only
#include "Ar9565NativePci.hpp"
#if !defined(__x86_64__)
#error The native PCI backend requires the Intel ABI
#endif
#include <IOKit/IOLib.h>
#include <libkern/OSByteOrder.h>
#include <stdint.h>

namespace simpleath
{
    namespace
    {
        // Check overlap without adding untrusted pointer lengths or wrapping
        // an address-sized integer. A single byte checks an opaque context's
        // known base, not the extent of its caller-owned allocation.
        bool overlapsStorage(const void *first, size_t firstLength,
                             const void *second, size_t secondLength)
        {
            if (!first || !second || !firstLength || !secondLength)
                return false;
            const auto left = reinterpret_cast<uintptr_t>(first);
            const auto right = reinterpret_cast<uintptr_t>(second);
            return left >= right ? left - right < secondLength
                                 : right - left < firstLength;
        }
    } // namespace

    NativePciBackend::NativePciBackend()
        : owner_(nullptr), pci_(nullptr), bar_(nullptr), power_ {}, length_(0),
          powerCapability_(0), configured_(false), claimed_(false),
          dmaEnabled_(false)
    {
    }

    NativePciBackend::~NativePciBackend()
    {
        // Explicit session.stop(), followed by clear(), is required under the
        // owner's lifecycle serialization. Never infer D0 or close an active
        // provider implicitly during object destruction in an unknown context.
        if (configured_ || claimed_ || bar_)
            IOLog("SimpleATH: uncleared native PCI backend retained; teardown "
                  "incomplete\n");
    }

    bool NativePciBackend::configure(IOService *owner, IOPCIDevice *pci,
                                     const NativePciPowerGate &power)
    {
        if (configured_ || claimed_ || bar_ || owner_ || pci_ || !owner ||
            !pci || !power.context || !power.isConfirmedD0 ||
            owner->isInactive() || pci->isInactive() ||
            owner->getProvider() != pci)
            return false;
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
            return {};
        return {this,           claim,   release,   inD0,    configRead32,
                commandWrite16, mapBar0, unmapBar0, readBar0};
    }

    bool NativePciBackend::clear()
    {
        if (claimed_ || bar_ || dmaEnabled_)
            return false;
        configured_ = false;
        power_ = {};
        length_ = 0;
        powerCapability_ = 0;
        if (pci_)
        {
            pci_->release();
            pci_ = nullptr;
        }
        if (owner_)
        {
            owner_->release();
            owner_ = nullptr;
        }
        return true;
    }

    bool NativePciBackend::claim(void *context)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if (!self.configured_ || self.claimed_ || self.bar_ ||
            self.owner_->isInactive() || self.pci_->isInactive() ||
            self.owner_->getProvider() != self.pci_ ||
            self.pci_->isOpen(nullptr))
            return false;
        // IOPCIDevice's provider open protocol is the ownership operation.
        // A registry match/category is not a claim. Do not seize another
        // client.
        if (!self.pci_->open(self.owner_, 0, nullptr))
            return false;
        if (!self.pci_->isOpen(self.owner_) || self.pci_->isInactive())
        {
            self.pci_->close(self.owner_);
            return false;
        }
        UInt8 capability = 0;
        const UInt32 header = self.pci_->findPCICapability(
            kIOPCICapabilityIDPowerManagement, &capability);
        if (!header || header == UINT32_MAX || capability < 0x40 ||
            capability > 0xf8 || (capability & 3U))
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
            self.pci_->close(self.owner_);
        // configure() references survive until explicit clear(); no driver
        // config or MMIO operation is issued from this release callback.
    }

    bool NativePciBackend::inD0(void *context)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        return self.configured_ && self.claimed_ &&
               !self.owner_->isInactive() && !self.pci_->isInactive() &&
               self.owner_->getProvider() == self.pci_ &&
               self.pci_->isOpen(self.owner_) &&
               self.power_.isConfirmedD0(self.power_.context) &&
               self.powerCapability_ &&
               (self.pci_->extendedConfigRead16(self.powerCapability_ + 4) &
                kPCIPMCSPowerStateMask) == kPCIPMCSPowerStateD0;
    }

    bool NativePciBackend::configRead32(void *context, uint16_t offset,
                                        uint32_t *value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if (!value || (offset & 3U) || offset > 0xfcU ||
            overlapsStorage(value, sizeof(*value), &self, sizeof(self)) ||
            overlapsStorage(value, sizeof(*value), self.power_.context, 1) ||
            (self.bar_ && overlapsStorage(value, sizeof(*value),
                                          reinterpret_cast<const void *>(
                                              self.bar_->getVirtualAddress()),
                                          self.length_)) ||
            !inD0(context))
            return false;
        const uint32_t observed = self.pci_->extendedConfigRead32(offset);
        if (observed == 0xffffffffU)
            return false;
        *value = observed;
        return true;
    }

    bool NativePciBackend::commandWrite16(void *context, uint16_t value)
    {
        uint32_t current = 0;
        if ((value & 0x0004U) || !configRead32(context, 0x04, &current) ||
            ((static_cast<uint16_t>(current) ^ value) & ~0x0002U) ||
            !inD0(context))
            return false;
        auto &self = *static_cast<NativePciBackend *>(context);
        // Never write PCI status at 0x06, enable DMA, or change other command
        // bits. The portable session reads command back and retains any restore
        // obligation.
        self.pci_->extendedConfigWrite16(0x04, value);
        return true;
    }

    bool NativePciBackend::mapBar0(void *context, uint32_t *lengthBytes)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if (!lengthBytes ||
            overlapsStorage(lengthBytes, sizeof(*lengthBytes), &self,
                            sizeof(self)) ||
            overlapsStorage(lengthBytes, sizeof(*lengthBytes),
                            self.power_.context, 1) ||
            (self.bar_ && overlapsStorage(lengthBytes, sizeof(*lengthBytes),
                                          reinterpret_cast<const void *>(
                                              self.bar_->getVirtualAddress()),
                                          self.length_)))
            return false;
        *lengthBytes = 0;
        if (self.bar_ || !inD0(context))
            return false;
        uint32_t command = 0, bar = 0, upper = 0;
        if (!configRead32(context, 0x04, &command) ||
            (command & 0x0006U) != 0x0002U ||
            !configRead32(context, 0x10, &bar) || (bar & 0x09U))
            return false;
        const uint32_t kind = (bar >> 1) & 3U;
        if (kind != 0 && kind != 2)
            return false;
        if (kind == 2 && !configRead32(context, 0x14, &upper))
            return false;
        if (!(bar & 0xfffffff0U) && !upper)
            return false;
        // Map the PCI family's assigned BAR by CONFIG REGISTER, never array
        // index, raw physical address, an injected registry value, or
        // destructive BAR sizing.
        IOMemoryMap *mapping =
            self.pci_->mapDeviceMemoryWithRegister(0x10, kIOMapInhibitCache);
        if (!mapping)
            return false;
        const auto length = mapping->getLength();
        const auto address = mapping->getVirtualAddress();
        // The provider supplies a virtual address and length separately.
        // Reject a wrapping window before publishing it or later deriving
        // a register pointer by adding an offset to the mapped base.
        if (!inD0(context) || !address || (address & 3U) ||
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
        IOMemoryMap *mapping = self.bar_;
        // Revoke the pointer/length before releasing the provider-owned map.
        self.bar_ = nullptr;
        self.length_ = 0;
        if (mapping)
            mapping->release();
    }

    bool NativePciBackend::readBar0(void *context, uint32_t offset,
                                    uint32_t *value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if (!value || !self.bar_ ||
            overlapsStorage(value, sizeof(*value), &self, sizeof(self)) ||
            overlapsStorage(value, sizeof(*value), self.power_.context, 1) ||
            overlapsStorage(
                value, sizeof(*value),
                reinterpret_cast<const void *>(self.bar_->getVirtualAddress()),
                self.length_) ||
            !inD0(context) ||
            (offset != kRevisionRegister && offset != kRtcStatusRegister &&
             offset != kEepromStatusRegister) ||
            offset > self.length_ || self.length_ - offset < sizeof(uint32_t))
            return false;
        const auto address = self.bar_->getVirtualAddress();
        // A mapping invalidated or unexpectedly changed after publication
        // must never wrap the address calculation in OSReadLittleInt32.
        if (!address || (address & 3U) || self.length_ > UINTPTR_MAX - address)
            return false;
        // The pinned SDK's OSSynchronizeIO is empty on Intel. Use Clang's full
        // hardware/compiler fence around the volatile little-endian MMIO load.
        __sync_synchronize();
        const uint32_t observed =
            OSReadLittleInt32(reinterpret_cast<const volatile void *>(
                                  static_cast<uintptr_t>(address)),
                              offset);
        __sync_synchronize();
        if (observed == 0xffffffffU)
            return false;
        *value = observed;
        return true;
    }

    bool NativePciBackend::setBusMasterGated(bool enabled)
    {
        uint32_t command = 0;
        if (!bar_ || !inD0(this) || !configRead32(this, 0x04, &command) ||
            (command & 2U) == 0U)
            return false;
        const uint16_t desired =
            static_cast<uint16_t>(enabled ? command | 4U : command & ~4U);
        // Do not write PCI status or alter unrelated command bits.
        pci_->extendedConfigWrite16(0x04, desired);
        uint32_t observed = 0;
        if (!configRead32(this, 0x04, &observed) ||
            static_cast<uint16_t>(observed) != desired || !inD0(this))
            return false;
        dmaEnabled_ = enabled;
        return true;
    }

    RegisterBus NativePciBackend::activeRegisters()
    {
        if (!bar_ || !inD0(this))
            return {};
        return {this, readActive, writeActive, length_};
    }

    bool NativePciBackend::readActive(void *context, uint32_t offset,
                                      uint32_t *value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        if (!value || !self.bar_ || !inD0(context) || (offset & 3U) ||
            offset > self.length_ || self.length_ - offset < sizeof(uint32_t) ||
            overlapsStorage(value, sizeof(*value), &self, sizeof(self)) ||
            overlapsStorage(
                value, sizeof(*value),
                reinterpret_cast<const void *>(self.bar_->getVirtualAddress()),
                self.length_))
            return false;
        const auto address = self.bar_->getVirtualAddress();
        if (!address || self.length_ > UINTPTR_MAX - address)
            return false;
        __sync_synchronize();
        const uint32_t observed = OSReadLittleInt32(
            reinterpret_cast<const volatile void *>(address), offset);
        __sync_synchronize();
        if (!inD0(context))
            return false;
        // EEPROM/OTP data can legitimately contain all-one words.
        *value = observed;
        return true;
    }

    bool NativePciBackend::writeActive(void *context, uint32_t offset,
                                       uint32_t value)
    {
        auto &self = *static_cast<NativePciBackend *>(context);
        uint32_t command = 0;
        if (!self.bar_ || !configRead32(context, 0x04, &command) ||
            (command & 0x0006U) != (self.dmaEnabled_ ? 0x0006U : 0x0002U) ||
            (offset & 3U) || offset > self.length_ ||
            self.length_ - offset < sizeof(uint32_t))
            return false;
        const auto address = self.bar_->getVirtualAddress();
        if (!address || self.length_ > UINTPTR_MAX - address || !inD0(context))
            return false;
        __sync_synchronize();
        OSWriteLittleInt32(reinterpret_cast<volatile void *>(address), offset,
                           value);
        __sync_synchronize();
        // A same-device MMIO read drains posted writes before the reset
        // code starts measuring its pulse or delay. SREV is read-only.
        uint32_t revision = 0;
        return readActive(context, kRevisionRegister, &revision) &&
               revision != UINT32_MAX;
    }

} // namespace simpleath
