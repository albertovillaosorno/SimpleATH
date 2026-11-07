# Static ABI evidence acquisition for native PCI and Wi-Fi

No native backend is authorized or enabled by this workflow. Source inspection
does not require an experimental build or physical card access.

## Current evidence and exact missing contracts

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
not a final KPI export allowlist. The binary-input path is source only and has
not been exercised or tested; only the retained JSON-input inspection was run.

Mach-O format references:
[Apple's loader definitions](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h)
and [nlist definitions](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/nlist.h).
No Apple implementation code is copied into the tool.

## Approval still requires stronger evidence

Neither inventory mode can set nativePciAbiVerified or nativeWirelessAbiVerified
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
