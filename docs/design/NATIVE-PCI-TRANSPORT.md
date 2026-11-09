# Native PCI read-only transport — disabled, uncompiled source

`src/platform/Ar9565NativePci.*` now implements the existing
PciSessionBackend contract using IOPCIFamily objects. The source is included
in the Xcode target, behind `SIMPLEATH_ENABLE_EXPERIMENTAL_PCI_BACKEND=0`.
The passive IOService does not instantiate it, and its plist still has no PCI
dependency. No compilation, tests, provider open, BAR mapping, physical config
read, MMIO or power transition was performed.

## Ownership and scope

configure retains the controlling IOService and IOPCIDevice, but only if
the PCI function is the service's direct provider; a different PCI device may
not be handed to an unrelated owner. Claim and D0 checks also reject a
service whose provider has changed since configuration. A successful claim
requires no existing provider open, then uses open(owner, 0, nullptr)
without seizing another client and confirms isOpen(owner). The preflight
check is not the lock: the provider open protocol arbitrates ownership.
Apple's [IOPCIDevice source](https://github.com/apple-oss-distributions/IOPCIFamily/blob/main/IOPCIDevice.cpp)
delegates handleOpen to its superclass; the
[IOService contract](https://github.com/apple/darwin-xnu/blob/main/iokit/IOKit/IOService.h)
documents single-owner access for the default implementation. These sources
inform the contract; exact compiled target virtual dispatch still needs review.

Every callback must execute under the controlling service's lifecycle gate.
The backend does not create that gate or register a controlling service.
The power context must outlive configuration. inD0 additionally requires the
claim, active owner/provider objects, continued provider open and a positive
external power-management callback. That callback **must** represent confirmed
provider D0/accessibility and be revoked before power loss or termination.
There is no always-true callback or register/property substitute in this code.
A complete PCI/power owner remains a separate missing component.

PciReadOnlySession owns the physical-ID, class, header, BAR and silicon checks.
The adapter's config reader reads live extended configuration space, rejects
all-ones responses, and bounds accesses to aligned dwords in the first 256
bytes. No registry vendor/device values are used as physical identification.
The session rejects a 0030 spoof and inherited bus mastering before mapping.

## BAR, command and access limits

The native map path rechecks memory decode enabled and bus mastering disabled,
validates the assigned non-prefetchable memory BAR0 type/address, then calls
mapDeviceMemoryWithRegister(0x10, kIOMapInhibitCache). The PCI family selects its
assigned range by configuration register. No destructive BAR sizing, assumed
array index, user-injected address or raw physical-memory mapping is used.
Mapping success requires a nonzero aligned virtual address and a provider map
length covering the RTC status register without exceeding the 32-bit length
contract. The virtual base plus map length must also fit without integer
wraparound, including when the map address is retrieved again for a register
read. Failure releases the temporary map and publishes no mapping.

Native callback output pointers are checked before writing so a malformed
caller cannot overwrite the backend's ownership/callback storage, the known
start of its opaque power context, or the currently mapped BAR through a
read-only result buffer. The full size of an external power-context allocation
is unknown and must be kept disjoint by its owner.

Only 16-bit writes to PCI command are available. The adapter rejects bus-master
enable and any change other than memory-decode bit 1 relative to the current
word. It never writes PCI status. The portable session performs readback and
tracks/restores only the decode change it made; write-call return alone is not
proof of a hardware write. No RF, reset or DMA register writes exist here.

The native read callback independently restricts MMIO to SREV, RTC status and
EEPROM status, rechecks ownership/power/map bounds, and rejects all-ones reads.
The pinned OSByteOrder header implements a volatile 32-bit little-endian load.
Its OSSynchronizeIO helper is empty on Intel, so this source uses Clang's full
compiler/hardware fence around the load. There is no arbitrary register-read
escape through the supplied callback, including EEPROM/OTP trigger addresses.
The separate active NVM reader has no native capability connected to it yet.

The portable session now performs another owner-in-D0 check after the
entire read-only silicon inspection, before reporting success. In a synthetic
regression, the last EEPROM register read and its immediate D0 check succeeded,
but provider D0 vanished during subsequent core parsing. Previously inspection
could still report success; it now returns `NotInD0`, revokes the core and BAR,
and releases the claim without attempting a configuration rollback on a lost
provider. An unresolved memory-decode obligation remains recorded, preventing
unsafe reuse. This is an offline callback-boundary regression, not physical
power-management or native kernel evidence.

The same late-D0 rule applies after `mapBar0`: software-only device matching
and read-only core attachment must finish before one final D0 prepublication
check. A synthetic post-map owner callback can return true while revoking D0;
source now unwinds and reports `NotInD0` instead of publishing read access.
The outstanding decode rollback is retained on the unavailable-provider path.

## Teardown and remaining ABI work

PciReadOnlySession must revoke its core access and restore any decode obligation
while accessible, then unmap and release the claim. Native release revokes its
claim flag, clears the map pointer/length before releasing the map, and closes
only its successful provider claim. That callback performs no driver MMIO or
config access. Platform close implementation details remain the PCI family's
responsibility. It tolerates an already-closed or inactive provider object.

After session.stop, clear releases the configure references. It refuses while
a claim/map remains. Retaining the owner can otherwise form an ownership cycle;
explicit clear is mandatory. Unexpected destruction logs incomplete teardown
and retains resources instead of attempting hardware cleanup from an unknown
context. Production lifecycle/error recovery must prevent that case.

The exact 25G332 KDK supplies PCI 2.9 and the relevant config/map exports,
as recorded in [KDK evidence](TAHOE-25G332-KDK.md). This adapter uses named SDK
methods, never guessed vtable indexes or profile addresses. That does not
complete the pinned-header/target-vtable, KPI eligibility or production
collection provenance review. Before any active build, the controlling target
must explicitly declare the verified IOPCIFamily dependency and audit every
actual import/relocation, including the old RIP-relative failure path.
Enabling this macro alone is not a supported deployment recipe.

Native DMA worker/gate handoff, actual rings/interrupts, safe reset/wake,
calibration, legal power and native wireless are still incomplete. Neither
this source nor the packet-buffer resource class proves physical identity,
successful loading, scan, association, traffic or resume. All physical steps
remain subject to separate owner authorization.
