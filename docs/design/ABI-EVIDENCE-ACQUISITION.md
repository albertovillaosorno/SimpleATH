# Static ABI evidence acquisition for native PCI and Wi-Fi

No native backend is enabled by this workflow. Source inspection
does not require an experimental build or physical card access.

## Current evidence and exact missing contracts

The later [exact-build KDK inspection](TAHOE-25G332-KDK.md) supplements the
retained snapshot below. It supplies IOPCIFamily 2.9, both previously unresolved
PCI symbols in that package's export list, full wireless nlist candidates and
matching kernel/wireless/Skywalk UUIDs. The snapshot omissions remain
limitations
of that snapshot, not current claims that those APIs are absent. Native ABI
approval and loaded-image provenance remain incomplete.

The read-only inventory in
`docs/evidence/TAHOE-ABI-SYMBOL-INVENTORY.json` describes the pinned retained
Tahoe reference, not a freshly acquired collection from the Dell. It records
the reference SHA-256, profile/kernel/collection metadata, source-image UUIDs
and candidate symbol classifications without copying callable addresses.

The supplied reference has no IOPCIFamily image. Thus neither the previously
unresolved IOPCIDevice::metaClass nor extendedConfigRead16 can be checked
against their owning family's export evidence. No PCI native adapter can be
approved from this reference. This is missing evidence, not proof that Tahoe
removed those symbols. The passive target still declares no PCI-family import.

For the searched controller/interface class names, the IO80211Family snapshot
contains four reported metaclass exports (controller, Skywalk interface and
the two monitor classes). Its only recorded vtables are IO80211APIUserClient
and IO80211AsyncEventUserClient. It does not supply controller/interface
construction, superclass/instance layout, mandatory virtual-method calling
contracts or their packet/queue/key lifetimes. A user-client table cannot be
substituted for these controller/interface contracts. Recorded symbol absence
does not prove absence from the complete OS image.

The five searched kernel DMA symbols are reported as exported by the snapshot:
IODMACommand's metaclass, OutputHost32/OutputHost64, withSpecification and
IOMapper's metaclass. That is not evidence of a verified device mapper,
DMA-command lifetime or correct descriptor addressability for the Dell.

## Read-only inventory tool

### Copy existing evidence from the target installation

`tools/collect_platform_abi.py` is a separate, source-only collector. It has
not been run on the Dell or tested. When the owner chooses to collect files,
run it manually on the Intel Mac using Python 3, without sudo:

```sh
python3 -B tools/collect_platform_abi.py \
  --expected-build 25G332 \
  --output "$HOME/Downloads/SimpleATH-ABI-25G332"
```

The output directory must not already exist. The script checks the source
SystemVersion build before creating it, copies the existing Boot/System
kernel collections, kernel and three families' Info.plist/executable files
when accessible, and records sizes, SHA-256 hashes and unavailable paths in
manifest.json. Missing standalone executables are not proof of missing
families: those families may be present in a collection. Failure to copy the
version and Boot collection produces a failure status, without privilege
escalation or any automatic retry.

For an already accessible offline OS root, add `--source-root /path/to/root`.
The script does not mount volumes, fetch/install a KDK, invoke a kernel
utility, execute a driver, probe PCI, change network state or touch EFI.
It writes copies only to a new directory under home or the temporary
directory, rejecting system/EFI output paths. The resulting files need to be
transferred separately for inspection; no upload happens automatically.
Matching the observed build is not proof of loaded-image provenance, native
wireless compatibility or an unpatched installation.

### Inspect already acquired files

To inspect the retained JSON reference:

```sh
python3 -B tools/inspect_platform_abi.py \
  --reference src/platform/abi/Tahoe.json
```

The tool checks the neighboring manifest hash when supplied and distinguishes
snapshot-reported exports from symbols not reported as exports. It reads data
and writes JSON to standard output. It does not execute a test suite, compiler,
target code, workflow, system/kernel utility, PCI access or volume operation.

When an exact-target collection and optional SystemVersion.plist have already
been acquired through an authorized process, they can be inspected as files:

```sh
python3 -B tools/inspect_platform_abi.py \
  --collection /approved/offline/BootKernelExtensions.kc \
  --system-version /approved/offline/SystemVersion.plist
```

Those paths are examples, not existing files or acquisition commands. The tool
does not acquire them, inspect a running machine or prove that the two files
came from the same installation. Acquisition that accesses the Dell or modifies
storage remains subject to the owner's separate authorization.

The collection reader accepts thin little-endian x86_64 MH_FILESET files,
bounds load commands/strings/nlists, records image UUIDs and inventories public
N_SECT/N_ABS nlist definitions while excluding STAB, undefined and private
external entries. The symbol classification is deliberately a **candidate**,
not a final KPI export allowlist. The collection/fileset path has not been
exercised or tested. The later KDK inspection below does not exercise filesets.

The KDK mode reads already extracted package files, selects bounded x86_64
Mach-O slices, and records family versions/dependencies and per-file/slice
hashes. For PCI it additionally intersects nlist candidates with the packaged
IOPCIFamily.exports file. It does not execute the package, install it, load
kernel code, or approve an adapter:

```sh
python3 -B tools/inspect_platform_abi.py \
  --kdk-root /path/to/extracted/KDK/root
```

This mode was used for static inspection of the actual downloaded 25G332 KDK,
producing `docs/evidence/TAHOE-25G332-KDK-SYMBOLS.json`. Its binary nlist/slice
path has thus been exercised on those files, without a test suite or driver
build. The kernel-collection/fileset input path remains unexercised.

Mach-O format references:
[Apple's loader
definitions](https://github.com/apple-oss-distributions/xnu)
and [nlist
definitions](https://github.com/apple-oss-distributions/xnu).
No Apple implementation code is copied into the tool.

## Exact-build kernel DMA type observations (static DWARF)

The bounded, source-only [25G332 kernel type
record](../evidence/TAHOE-25G332-KERNEL-DMA-TYPES.json)
preserves the relevant LLDB type metadata from the already-extracted KDK
kernel and its matching dSYM. The inspected kernel SHA-256 is
`a91aad0da9d0a2f545c06859524bb048f4e2e392e46aa12da9fabe652081be53`;
the kernel dSYM DWARF SHA-256 is
`44b7b1549ad61149f17bf763b14664fc91b1cd39c428ba41459008def988963d`.
This is metadata only (names, declarations, direct-field offsets and type
sizes), not Apple implementation code, a loaded-image record or a runnable
binary. The LLDB target was created for a file with scripts disabled; no
process was launched or attached. The original extracted sources remain
outside the repository.


- **KDK type:** `IOMapper`
  - **Observed bytes:** 208
  - **Scoped source API evidence:** `copyMapperForDevice(IOService *)`

- **KDK type:** `IOBufferMemoryDescriptor`
  - **Observed bytes:** 232
  - **Scoped source API evidence:** Both `inTaskWithOptions` factory overloads
    and `getBytesNoCopy`

- **KDK type:** `IODMACommand`
  - **Observed bytes:** 120
  - **Scoped source API evidence:** Both `withSpecification` overloads and
    `setMemoryDescriptor`, `prepare`, `complete`, `synchronize`,
    `genIOVMSegments`, `clearMemoryDescriptor`

- **KDK type:** `IOMemoryDescriptor`
  - **Observed bytes:** 96
  - **Scoped source API evidence:** `prepare`, `complete`, `readBytes`,
    `writeBytes`

- **KDK type:** `IOMemoryMap`
  - **Observed bytes:** 88
  - **Scoped source API evidence:** `getVirtualAddress`, `getLength`

- **KDK type:** `IOWorkLoop`
  - **Observed bytes:** 72
  - **Scoped source API evidence:** `inGate`, `onThread`

- **KDK type:** `IOService`
  - **Observed bytes:** 136
  - **Scoped source API evidence:** `open`, `close`, `isOpen`, `isInactive`


An immediate SDK-versus-KDK declaration distinction matters for the disabled
`NativeDmaBuffer`: the pinned MacKernelSDK factories return raw pointers, while
the KDK DWARF describes `OSPtr<T>` for `copyMapperForDevice`,
`inTaskWithOptions` and `withSpecification` (canonical types are `T *`).
Those declarations have matching parameter/mangled forms; an `OSPtr` spelling
alone does **not** prove changed x86_64 return registers, object ownership,
reference counts, or safe linking. The static KDK disassembly of
`IOBufferMemoryDescriptor::inTaskWithOptions` showed its result in `%rax`, not
a hidden structure-return pointer, but that observation also cannot verify the
caller contract for all factories. Do not blindly adopt/release a returned
pointer until each ownership contract is established.

The extracted type fields are **not** a full inherited layout or vtable map.
In particular, no virtual dispatch slot, provider lifetime, IOMMU mapping
contract, KPI production export eligibility, or exact Dell loaded-image
provenance was approved. These remain blocking dependencies for the inactive
native PCI/DMA implementation; the recorded booleans stay false. No kext
build, platform-ABI collector run, device access, or physical test was
performed for this evidence addition.

## Approval still requires stronger evidence

No inventory mode can set nativePciAbiVerified or nativeWirelessAbiVerified
to true. A complete review must additionally establish:

- Exact target build/provenance, collection/image UUIDs and source-file hashes.
- PCI/KPI dependencies, version compatibility, actual export allowlists,
  export tries, aliases/reexports and symbol eligibility for this driver.
- Verified C++ instance layout, virtual-method positions/signatures and the
  native wireless control, security, packet, power and teardown contracts.
- After separate build authorization, the actual compiled imports and every
  relevant relocation, including the prior RIP-relative failure path.
- After separate installation/device authorization, actual injection/loading,
  physical identity, calibrated radio, legal TX, wireless association and data.

This inventory narrows missing evidence. It is not a replacement for any of
those steps, an ABI checker with a passing grade, or a native Wi-Fi interface.
