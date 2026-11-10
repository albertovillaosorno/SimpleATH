# Native macOS integration decision and evidence

Source inspection: 2026-11-06. Target supplied by the owner: x86_64 Tahoe
26.7.2 / 25G332, Dell Inspiron 5567, physical PCI 168c:0036.
No compilation, tests, kernel loading, hardware access or EFI changes were
performed for this record. All new source remains uncompiled.

## Decision

The owner replaced the passive-only policy on 2026-11-09. The normal target
now runs the PCI/RTC/NVM owner; implement the remaining radio/queue/native
wireless path before speculative hardening. Preserve
an explicit PCI session contract; do not recover access through raw physical
addresses, guessed vtable slots, kernel symbol scanning or a second owner.
The intended in-kernel path is IOPCIFamily + IODMACommand + a verified
IO80211/Skywalk controller/interface. The native wireless adapter is blocked,
not implemented by the retained Broadcom bridge.

A signed PCIDriverKit extension is an alternative PCI transport, subject to
Apple's signing and PCI entitlements. It cannot share this PCI function with
a kext. Moving PCI access there does not solve the native wireless interface.
Apple explicitly limits NetworkingDriverKit to Ethernet; an Ethernet packet
bridge must not be represented as native Wi-Fi. See Apple's
[PCI network-driver guidance](https://developer.apple.com/documentation/pcidriverkit/connecting-a-network-driver)
and [NetworkingDriverKit](https://developer.apple.com/documentation/networkingdriverkit).

## What the local ABI evidence establishes

The later [25G332 KDK inspection](TAHOE-25G332-KDK.md) supplies exact-build
package evidence beyond the retained snapshot described below. The x86_64
IOPCIFamily 2.9 UUID is `227771C6-ADC2-30C7-8408-263F723CF81C`. Both old
unresolved imports, metaClass and extendedConfigRead16, occur in its nlist
and packaged export list. The package's kernel, IO80211 and Skywalk UUIDs
match their retained-reference UUIDs. Static PCI dSYM inspection also supplies
type observations. This narrows the missing evidence; it neither proves the
Dell loaded those files nor identifies the old artifact's complete failure.

Full wireless nlists now supply constructors and vtable names missing from
the snapshot. For example native attachInterface takes OSObject/IOService,
which differs from the legacy interface-pointer/bool signature. Effective
wireless exports, full types/virtual contracts and packet/key lifetimes still
need verification. The native PCI adapter is now integrated; the wireless adapter remains required.

`src/platform/abi/Tahoe.json` has SHA-256
`611b50f109954bb7eda873c40dccf7f6d3ff57a994a156ede9550d9ac9ce82cd`,
matching its manifest. This is a retained SimpleBCM reference, not a fresh
extraction from this Dell. Its profile says 25G332, kernel version 25.6.0,
collection UUID `4bf8cd701d60637fdd1aca7be2d3d846`.

It contains exactly three images: kernel, IOSkywalkFamily and IO80211Family.
**It contains no IOPCIFamily image.** Its absence cannot establish that any
IOPCIDevice symbol is missing from Tahoe. The current Info.plist declares IOPCIFamily 2.9. The old injection error establishes failure of that
artifact's resolution, not the unavailability of the entire PCI API.

The pinned MacKernelSDK (`3f750085caa17ec3a7880f11c11bf4f48cd6a164`)
[IOPCIDevice header](https://github.com/acidanthera/MacKernelSDK/blob/3f750085caa17ec3a7880f11c11bf4f48cd6a164/Headers/IOKit/pci/IOPCIDevice.h)
inlines `configRead16` into nonvirtual `extendedConfigRead16`. Renaming the
call to configRead16 therefore does not remove that import. Header SHA-256:
`64a32261140503d1b332dd67ab656d3f79e946f223a730ad739b81fe5bb5ae3a`.
The pinned SDK's `IODMACommand.h` SHA-256 is
`35d9513d987857f08df26b85ab664791feac444f504c05241c0a93aa6faec43d`.
Headers establish declarations, not target-kernel exports or ABI compatibility.

The reference contains IODMACommand factories/output helpers and native
IO80211Controller/IO80211SkywalkInterface metaclasses. These do not establish
the constructors, superclass layouts, required virtuals, selector semantics,
packet queues, events or key installation contract for an Atheros controller.
`NativeSkywalk.cpp` constructs an Ethernet wrapper around a Broadcom legacy
interface; it and `WirelessABI.hpp` remain outside the SimpleATH source phase.
Do not activate them by renaming classes or importing profile addresses.

Before enabling a PCI backend, correlate the package evidence with the exact
target's installed/loaded collections, complete the SDK/virtual-method and
kernel/KPI dependency comparison, and establish ownership/power/mapper
contracts. After separate build authorization, inspect every undefined
symbol and relocation in the resulting Mach-O against that dependency graph.
Symbol presence alone does not establish C++ layout or successful OpenCore
injection. Do not use the stored absolute addresses as callable addresses.

The [ABI evidence acquisition record](ABI-EVIDENCE-ACQUISITION.md) now provides
a read-only inventory tool and checked-in reports for the retained reference
and extracted KDK files.
It distinguishes missing images and snapshot export claims from global nlist
candidates; it deliberately cannot approve the native PCI or wireless ABI.

## Ownership, configuration and BAR contract

1. One controlling IOService owns the PCI function. A custom IOMatchCategory
   only controls matching competition; it is not an exclusive hardware claim.
   Claim through the PCI provider's open protocol before touching config/MMIO,
   retain the provider for the whole session, and stop if another owner exists.
2. Serialize hardware start/stop, power, interrupts and recovery on one work
   loop/gate. Blocking buffer allocation and IODMACommand preparation must run
   on a separate sleepable client thread. Reserve lifetime/epoch under the
   gate, allocate privately, then reenter the gate and reject stale epochs
   before publishing any device address. See
   [native DMA buffers](NATIVE-DMA-BUFFERS.md) for the normally compiled resource
   implementation and the controller/worker integration still required.
   Establish D0 through the PCI/power family and observe completion before
   config/MMIO. A boot argument or a registry property cannot establish D0.
3. Read physical vendor/device, subsystem, class and header from configuration
   space after ownership. Registry vendor-id/device-id are diagnostic only.
   Reject 0030 even if OpenCore matched it. Require 0036 and the true SREV.
4. Reject an inherited bus-master-enabled device in the first read-only
   milestone. Do not silently take over or assume its DMA has stopped. A later
   recovery backend must implement a bounded hardware quiesce/reset first.
5. Select BAR0 by its PCI register (0x10), not an assumed memory-array index.
   Use the PCI family's assigned IODeviceMemory and an uncached mapping.
   Validate memory BAR type, assigned address, length and overflow. Never
   probe BAR sizing by writing all ones. Never manufacture a map from a
   registry address or call physical-memory mapping APIs to bypass IOPCIFamily.
6. Change only the 16-bit PCI command word when enabling memory decode;
   a 32-bit read/modify/write can clear write-one-to-clear PCI status bits.
   Read back command and ensure bus mastering stays clear. Unwind partial
   failures, restoring only memory decode changed by this session. Never
   restore an old bus-master bit. Revoke all register callbacks before unmap.
7. Read little-endian aligned 32-bit registers with ordering and bounds checks.
   A read-only diagnostic bus admits only SREV, RTC status and EEPROM status;
   EEPROM/OTP trigger registers are not innocuous passive reads.

Apple's public [IOPCIDevice implementation](https://github.com/apple-oss-distributions/IOPCIFamily/blob/main/IOPCIDevice.cpp)
delegates handleOpen to IOService's ownership protocol. Its DriverKit-specific
close path disables memory/bus leading; a kext must not assume that DriverKit
cleanup runs for a normal kernel client. Public source is architectural
evidence, not an exact 25G332 ABI or implementation attestation. No Apple
implementation source is copied into SimpleATH.

## DMA, interrupts, power and teardown contract

The read-only PCI session deliberately has no bus-master enabling, MMIO writes,
DMA or interrupt operations. Those are separate implementation blockers.

For the data path, obtain the device's IOMMU mapper through verified PCI/IOKit
APIs. Use IODMACommand with mapped addressing, the actual descriptor address
width, alignment, segment and transfer limits. Allocate/prepare descriptor and
payload memory, retain each descriptor/command until DMA completion, and program
only generated I/O virtual addresses. CPU pointers and getPhysicalSegment are
not DMA addresses. Do not request bypassed mapping or disable VT-d to make an
address fit. Reject incomplete mappings, boundary violations and truncation.

Prepare rings before bus mastering; install disabled interrupt sources on the
same work loop, clear stale causes in a device-specific sequence, then enable
only implemented causes. Shared INTx requires ownership filtering and bounded
draining; MSI availability must be discovered. Hard interrupt work must not
allocate memory, wait for the gate, or process 802.11 frames. Deferred processing
must validate ownership/status before recycling buffers. The ath9k enhanced DMA
descriptors, TX status ring and RX queues require a real port, not generic ring
structures named after ath9k.

Stop new submissions first, mask device interrupts, drain callbacks and timers,
stop TX/RX engines with bounded timeouts, disable PCI bus mastering and confirm
quiescence, then complete/clear mappings and release packet/ring memory. If
quiescence cannot be proven, quarantine DMA memory until a verified reset or
PCI isolation makes release safe. An unresponsive device must not cause an
unbounded wait or use-after-free. Remove event sources before releasing the
work loop and close the provider last. Every partially completed start needs
the same reverse ownership order.

Before D3/sleep, run that quiesce sequence, invalidate board/channel/key/session
state as appropriate, and revoke MMIO access before provider power falls.
Resume must reacquire D0, revalidate physical identity/SREV, reestablish BAR and
DMA mappings, reset/recalibrate, restore regulatory constraints, rebuild rings
and reconnect. Never reuse stale DMA addresses or assume association survived.
Surprise removal forbids subsequent MMIO/config accesses; backend teardown must
account for it. The portable session has an explicit inaccessible-provider path.

## Native wireless blocker and acceptance

No verified Tahoe Atheros Wi-Fi subclass, control client, scan/association
selector implementation, key path or packet delivery backend exists here.
Exact-build IO80211/Skywalk evidence must establish those contracts before the
interface is registered. This remains an open blocker, not proof that a native
implementation is impossible.

Never transmit (including probe/authentication frames) before complete board
calibration, RF-kill/coexistence configuration and regulatory/channel/power
approval. Passive scanning still needs a working RX/DMA/beacon path.

See AR9565-BRINGUP.md for implementation status. Build/import inspection,
installation and physical validation each require renewed, explicit owner
authorization. Desktop boot, a registered IOService, or an Xcode success is
not wireless acceptance.
