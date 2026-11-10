# Tahoe 25G332 KDK: static PCI and wireless evidence

Inspected on 2026-11-07 UTC after the owner requested an online/Downloads
search. No installer, mount, compilation, test suite, process launch/attach,
PCI transaction, kernel load or EFI change was performed.

## Current integration update — 2026-11-09

The historical inventory below predates native runtime integration. Current
`SimpleATH.cpp` owns PCI, runs RTC reset and acquires board NVM. Native PCI/DMA
implementations are now compiled without feature opt-ins, with an explicit
IOPCIFamily 2.9 dependency. All C++ source parses against the pinned SDK with
kernel declarations enabled. This does not establish binary linkage or a
working Wi-Fi interface; radio, queue/IRQ and IO80211 integration remain open.

## Acquisition and provenance

The [Dortania KDK manifest](https://raw.githubusercontent.com/dortania/KdkSupportPkg/gh-pages/manifest.json)
and [25G332 release](https://github.com/dortania/KdkSupportPkg/releases/tag/25G332)
provide Kernel Debug Kit 26.7.2 build 25G332, published November 2. The existing
DMG was downloaded for static inspection, without executing the installer.
Its 1,181,052,767 bytes hash to SHA-256
`9490bd9b5e16ff5cee8b7330c498d64f27a008aa91c5c70d686a00dc5978c555`,
matching that manifest. This is mirror/hash provenance, not an independent
verification of Apple's package signature or the Dell's loaded images.

Only archive entries needed for inspection were unpacked to
`/tmp/simpleath-abi-25G332`. The KDK's SystemVersion.plist reports 26.7.2 /
25G332. No Apple executable, implementation, header or debug-symbol file is
added to the repository: the evidence records contain hashes, names and
observed ABI metadata only.

The XAR entries use inode zero. The installed archive reader incorrectly
made selected metadata entries hard links to the large Payload. That metadata
was discarded as evidence. The relevant metadata was instead read by its XAR
TOC offset/length and checked against the TOC's extracted SHA-1, while the KDK
Payload was read as PBZX/XZ plus ODC CPIO. No package scripts were executed.
This extraction detail matters when reproducing the evidence.

Records:

- `docs/evidence/TAHOE-25G332-KDK-ACQUISITION.json`: archive provenance,
  debugger type observations and the rejected local candidate.
- `docs/evidence/TAHOE-25G332-KDK-SYMBOLS.json`: input/slice hashes, family
  versions/dependencies, UUIDs and classified symbol names; no callable addresses.

## What changed in the PCI evidence

| x86_64 image | Version | UUID |
| --- | --- | --- |
| IOPCIFamily | 2.9, compatible 1.0.0b1 | 227771C6-ADC2-30C7-8408-263F723CF81C |
| IO80211Family | 1200.13.1 | 4C2B4969-2B92-3646-9512-C1769BE0F9A4 |
| IOSkywalkFamily | 1.0 | A6EDB8DB-175B-3A49-8919-5769FCDB6BED |
| kernel | See package/SystemVersion record | 28267FD5-3E1E-3686-8A1C-E73E2466FCFB |

The latter three UUIDs match the retained reference's respective images.
The previously absent PCI image is now available as package evidence.

Both old unresolved names are present in the x86_64 IOPCIFamily nlist **and**
its packaged `Resources/config/IOPCIFamily.exports` list:

- `__ZN11IOPCIDevice9metaClassE`
- `__ZN11IOPCIDevice20extendedConfigRead16Ey`

The same intersection includes extended config read/write 8/16/32,
get/mapDeviceMemoryWithRegister, setMemoryEnable, setBusMasterEnable,
findPCICapability and enablePCIPowerManagement. The report retains exact names.
IOPCIFamily's plist lists iokit/libkern/mach/private/unsupported KPI dependencies
at 8.0. Its export-list file has 388 entries, not all IOPCIDevice methods.

This is concrete evidence against treating the prior resolution failure as
proof that Tahoe removed those APIs. It does not identify the full cause of
that artifact's failure. The passive SimpleATH plist intentionally still has
no PCI-family dependency or native calls. A future active adapter must declare
its dependency explicitly and validate its actual imports/relocations after
build authorization; adding a plist entry alone cannot repair a RIP overflow.

Static LLDB loading of the matching PCI dSYM reports IOPCIDevice size 184 and
IOService size 136, with the instance fields recorded in the acquisition JSON.
LLDB initialization and symbol-file scripts were disabled; no process was
launched or attached. These package type observations are not a completed
SDK-vtable comparison, DMA ownership contract or proof of a runtime layout.

## Native wireless remains a concrete integration task

The full IO80211 KDK nlist contains controller and Skywalk-interface constructors,
init methods and vtables absent from the small retained snapshot. For example:

- `IO80211Controller::attachInterface(OSObject *, IOService *)`
- `IO80211SkywalkInterface::init(IOService *, ether_addr *)`
- `IO80211SkywalkInterface::inputPacket(IO80211NetworkPacket *, packet_info_tag *, ether_header *, bool *, bool)`

Those signatures are observations from mangled names, not verified calling
contracts. In particular the attach signature is different from the legacy
`attachInterface(IONetworkInterface **, bool)` assumption; legacy headers cannot
be substituted. Wireless global nlist definitions are classified as candidates:
no wireless config export list, effective production export eligibility, full
class layout, required virtual slots, queue/packet/key lifetime, selector/event
contract or native driver adapter has been verified by this work.

`<LOCAL_DOWNLOADS>/IO80211Family` is a different thin x86_64
image, UUID 07644D43-FC89-3B05-AC4F-2E47D1045F4E. Its build provenance is unknown
and it is rejected as exact-target evidence. No matching KDK directory or kernel
collection was found by the filename search in Downloads; installer and recovery
archives were left untouched.

The exact installed collections, native API contracts and actual artifact
relocations remain outstanding. Use the separate manual copy-only collector
in [ABI evidence acquisition](ABI-EVIDENCE-ACQUISITION.md) if the owner chooses
to provide the production files. Both native verification flags remain false;
there is still no operating Wi-Fi interface or physical networking result.

## Current kext target versus proposed ABI imports (source reconciliation)

Reviewed the checked-in Xcode target and Info.plist as source on
2026-11-07 UTC; did not build, link, run a validator test suite or inspect
an actual produced kext. **PBXFileReference and PBXBuildFile declarations do
not establish compilation**: only membership in the target's active
PBXSourcesBuildPhase does. This distinction matters when auditing presumed
Tahoe dependencies and a prior unresolved-import artifact.

| Source boundary | Checked-in target state | ABI implication |
| --- | --- | --- |
| `src/SimpleATH.cpp` | In the `SimpleATH` kext Sources phase; two passive `IOService` classes | No direct `IOPCIDevice`, native IO80211 or Skywalk controller call; exposes no usable Wi-Fi interface |
| `src/platform/Ar9565NativePci.cpp` | In kext Sources, but the former PCI opt-in defaulted to `0` (historical) | Active PCI/IOPCIDevice code is preprocessor-disabled unless explicitly enabled; cannot be counted as a verified import or tested owner |
| `src/platform/Ar9565NativeDma.cpp` | In kext Sources, but the former DMA opt-in defaulted to `0` (historical) | IODMACommand, IOMapper and memory-descriptor use is disabled, not available to the passive probe |
| `src/platform/Ar9565PciSession.cpp` and portable hardware/Wi-Fi sources | In kext Sources | Callback-driven models are not an `IOPCIFamily` or native wireless service implementation |
| `src/Bridge.cpp`, `src/Loader.cpp`, `src/NativeSkywalk.cpp`, `src/NativeUserClient.cpp` and legacy patch helpers | Have project file/build-file records, but are **not** in the active `SimpleATH` Sources phase | Their private symbols, embedded-payload assumptions and handcrafted Skywalk classes cannot be treated as imports of the current target or as a valid Tahoe wireless implementation |
| `src/platform/probe/main.mm` | In the separate `athprobe` tool Sources phase | A userspace inspection utility, not a kernel Wi-Fi controller or proof that its probed symbols are callable from the kext |

The checked-in `src/Info.plist` declares `com.apple.kpi.iokit`,
`com.apple.kpi.libkern`, `com.apple.kpi.mach` and
`com.apple.kpi.private`, but not `com.apple.iokit.IOPCIFamily`,
`com.apple.iokit.IO80211Family`, `IO80211FamilyLegacy` or
`IOSkywalkFamily`. Its passive PCI personality matches registry IDs
`168c:0036` **and** legacy `168c:0030`; `SimpleATH.cpp` explicitly marks
physical identity, MMIO, radio and native Wi-Fi readiness unverified or
false. Registry matching, especially a possibly OpenCore-spoofed ID, is
not a substitute for the future physical-identity/PCI ownership check.

`src/platform/Kernel.xcconfig` points to a separate research
MacKernelSDK header path (`.research/MacKernelSDK/Headers`), which is not
bundled in this working tree and is not automatically the 25G332 KDK.
Neither Xcode project membership nor symbol-name presence can settle the
actual compiler-selected header layout, virtual-method contracts, KPI
eligibility or relocations. There is **no target-native IO80211 controller or
interface subclass** wired into this Sources phase. Conversely, no active
legacy payload/NativeSkywalk import can be inferred merely because its source
file remains in the project navigator.

To close the P0 ABI dependency, separately determine the intended enabled
native PCI/DMA and wireless source set, derive its required C++ method and
virtual ABI from exact-target eligible headers/types, add the correct
family dependencies when those real imports are introduced, then inspect
every actual compiled undefined import and relocation **after** separate build
authorization. Reconcile the result with KDK export lists and the target's
loaded images. The current static evidence cannot approve enabling either
experimental backend or claiming native wireless readiness.

## Exact-build kernel DWARF type observations (not an ABI approval)

A matching x86_64 KDK kernel and kernel dSYM were loaded as **static files**
into LLDB with initialization and symbol-file scripts disabled, without a
process launch or attach. The selected output has been reduced to class sizes,
field offsets and method names/types in
`docs/evidence/TAHOE-25G332-KERNEL-DMA-TYPES.json`, with both source SHA-256
hashes; no Apple binary, executable address or implementation was retained.
This supplements, and does not replace, the separate PCI-family dSYM sizes
already reported above.

| Kernel type (static DWARF) | Size (bytes) | Selected native method evidence |
| --- | ---: | --- |
| `IOService` | 136 | `open(IOService*, IOOptionBits, void*)`, `close`, `isOpen`, `isInactive` |
| `IOMapper` | 208 | `copyMapperForDevice(IOService*)` reports `OSPtr<IOMapper>` return (canonical `IOMapper*`) |
| `IOBufferMemoryDescriptor` | 232 | `inTaskWithOptions(task_t, IOOptionBits, vm_size_t, vm_offset_t)` reports `OSPtr<IOBufferMemoryDescriptor>` (canonical pointer); `getBytesNoCopy()` returns `void*` |
| `IODMACommand` | 120 | `withSpecification(...)` reports `OSPtr<IODMACommand>` (canonical pointer); `prepare(UInt64, UInt64, bool, bool)`, `complete(bool, bool)` and `synchronize(IOOptionBits)` appear in the type record |
| `IOMemoryDescriptor` | 96 | `prepare(IODirection)`, `complete(IODirection)`, 64-bit byte-count `readBytes`/`writeBytes` |
| `IOMemoryMap` | 88 | `getVirtualAddress()` and `getLength()` use 64-bit result types |
| `IOWorkLoop` | 72 | `inGate()` and `onThread()` are reported as boolean methods |

In particular, the **nominal** `OSPtr<T>` result types for three factories
must not be silently treated as proof that a pinned research SDK declaration
using raw `T*` has the same calling convention, retained-object ownership,
destructor requirements or required link symbol. The extracted **canonical**
type is a pointer, but this alone does not settle C++ ABI lowering. The
compile-disabled native PCI/DMA adapters may use these factories only after
exact header/calling-convention and object-lifetime review, effective export
eligibility, dependency reconciliation and authorized compiled-relocation
inspection. The recorded field offsets are debugger descriptions, not a
license to dereference private fields or assert the target Dell's runtime
layout. All ABI verification flags remain false.
