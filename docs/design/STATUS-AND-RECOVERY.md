# Implementation status, blockers and recovery

Record: 2026-11-06. This record covers the committed source milestones below.
Concurrent agents may add further modules; source names or presence alone do
not establish that those modules are compiled, wired to hardware or validated.

## Committed source milestones

| Commit | Change | Verification actually performed |
| --- | --- | --- |
| 933a91e | PCI ownership, DMA/power/teardown architecture and exact limits of the stored Tahoe ABI reference | Source/header/reference inspection; Apple documentation consulted |
| 34d1941 | Portable exclusive PCI session orchestration, read-only register allowlist, cleanup paths and honest registry diagnostics | Static source/diff review; no native adapter or hardware access |
| d0b9176 | Bounded EEPROM block reconstruction, complete image storage and raw board summary | Static comparison to local permissive ath9k format/algorithms |
| 56c4564 | AR9565 board gain-index selection without generic chipset fallbacks | Static comparison to ar9003_hw.c and 1.1 aliases |
| 61a9dd0 | Concurrent descriptor/DMA metadata and management/EAPOL/data-frame modules | Source staged in target; no active DMA, crypto provider or OS interface |
| b0d729e | Bounded EEPROM chain restoration from an already acquired byte dump | Static bounds/order review; no EEPROM acquisition or runtime tests |
| 8035879 | Reject first-fragment decapsulation; fix WDS SA/DA and 4 GiB segment crossing | Static comparison to frame/address rules and descriptor bounds |
| da50d1e | Unique reservation generations reject stale DMA metadata completions | Static ownership/lifetime review; no hardware completion path |
| bedeba6 | Preserve Atheros descriptor notices and Linux source hashes | File-specific permissive-license and provenance inspection |
| 121c5fa | Read-only retained-reference/collection symbol inventory and explicit ABI-evidence gaps | Retained JSON inspected; binary-input reader source not exercised |
| 6bfda6d | Five pinned ath9k EEPROM reconstruction dictionaries and explicit lookup catalog | C++ source generation from pinned packed layouts/initializers; no C/C++ compilation or runtime vectors |
| 16d791a | Active EEPROM/OTP transaction reader with BAR, identity, word/capture timeout and output checks | Static comparison to permissive ath9k protocols; no backend attached or hardware transaction |
| 2f971e6 | EEPROM target/CTL power candidates, signed interpolation, HT/rate constraints and EIRP/antenna intersection | Static source comparison only; no calibration, legal-power approval, hardware TPC conversion or TX |
| 58ccdc7 | Manual copy-only collector for exact installed OS ABI files | Source review only; not executed on the Dell or tested |
| a3bbad8 | Exact 25G332 KDK acquisition, PCI nlist/export intersection, full wireless candidates and static PCI dSYM observations | Download hash matched published manifest; actual package files statically inspected; no installer, build, tests, process launch or device access |
| 609265d | Disabled native IOBuffer/IOMapper/IODMACommand packet-buffer resource source with client/gate handoff, 32-bit segment checks and epoch/allocation/submission retirement | Static pinned-header/KDK-symbol review only; no compilation, tests, native mapping or hardware transfer |

Both PCI-session and EEPROM implementations are in the SimpleATH Xcode Sources
phase. **Neither has been compiled or tested.** No build was made in this work.
The last authorized Intel build predates these modules and commit 2ca461c.
No new target-kernel load or wireless result exists.

The passive IOService does not instantiate the PCI session, read physical
configuration/MMIO, obtain exclusive ownership, enable bus mastering, allocate
DMA, request interrupts, or register a network interface. Registry-ID diagnostics
are explicitly marked as potentially spoofed. Passive matching publishes
`SimpleATHPortableCoreSourcePresent=true` but keeps
`SimpleATHHardwareCorePresent=false` until an actual PCI owner establishes
physical identity; diagnostic OSData payloads are also checked for accessible
bytes before decoding. Physical identity, SREV, EEPROM, regulatory approval,
association and traffic remain unverified/not implemented.

## Open blockers in dependency order

1. **Exact Tahoe PCI ABI:** the three-image retained profile omits IOPCIFamily,
   but the later exact 25G332 KDK supplies PCI 2.9, its UUID/dependencies,
   matching dSYM type observations and both old unresolved names in its
   packaged export list and x86_64 nlist. See TAHOE-25G332-KDK.md. Complete
   production collection provenance, pinned-SDK/virtual-method comparison,
   kernel/KPI eligibility and mapper/power contracts. Do not classify missing
   profile entries as missing OS APIs. Confirm all new compiled imports and relocations
   only after build authorization. The old RIP-relative/prelink failure is not
   evidence of a successful load or an explanation of every possible cause.
2. **Native wireless ABI:** the full KDK now supplies constructor/init/vtable
   symbol candidates absent from the retained snapshot. Establish effective
   exports, complete superclass layouts, mandatory virtuals, control
   selectors/events, packet queues, key paths and lifetimes for the intended
   Tahoe IO80211/Skywalk interface. The retained Broadcom
   Ethernet wrapper is not this implementation. No verified Atheros adapter
   exists. NetworkingDriverKit's Ethernet interface does not close this gap.
3. **Native PCI owner:** implement the serialized IOPCIFamily adapter for
   PciSessionBackend, including provider retention/open, D0, live config,
   BAR0 mapping, ordered access and termination/power handling. No boot option
   currently enables a backend. Native exports must be verified first.
4. **Board acquisition and reconstruction:** connect the staged bounded
   EEPROM/OTP reader to the verified PCI owner, implement source/origin
   discovery, and validate the staged dictionary serialization and dump-chain
   reconstruction against ath9k. No physical dump exists. The parser/catalog
   alone establishes no physical MAC, calibration validity or regulatory domain.
5. **Radio:** port reset/wake/PLL, PHY/RF sequencing, delays, synth/channel,
   board calibration, ANI/noise, antenna/RF-kill and Bluetooth coexistence.
   The 2,174 generated INI entries preserve HT20/HT40, gain variants and the
   separate 1.1 radio postamble; these remain data, not executed bring-up.
6. **Regulatory:** intersect verified board restrictions with a legitimate
   country/channel policy; implement CTL/target-power interpolation and
   per-rate conducted/EIRP limits before ANY transmission. Numerical target/
   CTL/EIRP candidates are staged in Ar9565Power; board/country authority,
   descriptor-power conversion and actual TPC remain missing. A parsed country
   field, recipe boolean or selected gain table does not establish permission.
7. **Data path:** implement actual IOMMU-backed descriptors/buffers, queue
   programming, interrupts, completions, recovery, bounded quiesce, suspend
   and resume. The disabled NativeDmaBuffer source now stages device-specific
   mapper/command packet allocations; it is uncompiled and unwired. Add the
   controller's client-worker/gate handoff and outstanding-operation lifetime,
   coherent descriptor/status-ring mapping and actual queue/completion paths.
   Neither portable ring metadata nor inactive native API calls move frames.
   Preserve memory until hardware is proven unable to DMA into it. Production
   quarantine/recovery is still missing; the staged resource deliberately
   retains memory after uncertain cleanup rather than freeing a DMA target.
8. **802.11/security:** connect actual received beacons to scan/BSS selection,
   authentication/association, WPA2/RSN/EAPOL/key/replay handling, rates,
   aggregation, disconnect/reconnect and OS packet delivery. Frame codecs or
   a station state machine alone do not establish association or key security.
9. **Validation:** necessary offline Python, C++ and Objective-C++ host tests
   are authorized under root `tests/` through `tools/validate.py --tests`.
   These may compile isolated host-only programs but never a kext or access
   hardware. Active kext compilation/CI and physical acceptance remain
   unauthorized and unperformed. Source formatting or host test success is
   not device readiness.

## Separate owner authorizations needed

These are future scopes, not authorization supplied by this document:

- **Kext build and import validation:** identify an immutable source commit;
  separately authorize compiling that exact commit on Intel macOS and
  inspecting its actual imports/relocations. Necessary isolated host tests
  are **already authorized** above, but do not authorize a kext build. If CI
  is chosen, separately authorize one named `build-v*` tag and its workflow.
  An ordinary main push remains source publication only and must not create
  any tag or dispatch.
- **Installation:** approve a specific reviewed artifact/hash and a specific
  disposable test EFI destination. Authorize only that copy/config change.
  Do not treat build approval as USB, EFI, SSD, root-patch or boot approval.
- **Physical validation:** authorize the device, artifact, boot and exact
  experiment scope. Start with injection/load and passive physical identity;
  obtaining EEPROM/OTP is a separate hardware step. Receive/scan, RF/TX/WPA2,
  traffic and sleep/coexistence need explicitly approved scopes as appropriate.
  TX also requires actual board calibration and regulatory approval in code.

No installation candidate is asserted ready by this record. Pending native
ABI, ownership and data-path blockers cannot be bypassed by owner consent.

## Recovery plan (instructions only; not executed)

Keep the known bootable **13-kext EFI** and every existing backup intact.
Before an authorized installation, inventory the test target and preserve its
original configuration and hashes. Never overwrite the only bootable EFI or
silently replace an SSD EFI. Do not install root patches as a workaround.

Keep a separate known-good boot path. If an authorized experimental boot
fails, boot that path and disable/remove only the experimental SimpleATH
entry from the test configuration, restoring the test backup if necessary.
`-simpleathoff` disables SimpleATH's service matching after its module start
can run; **it cannot fix OpenCore relocation, injection or prelink failure**.
Disabling injection in the test OpenCore configuration is the recovery for
that earlier stage. Recovery writes also require explicit owner authorization.

For each approved run record artifact/source hashes, OpenCore injection log,
kernel/build/UUID and IORegistry evidence. Wireless acceptance additionally
requires physical 168c:0036 + recognized SREV, 2.4 GHz scan, real WPA2
association/key security, DHCP/DNS/TCP traffic, reconnect after sleep, BT
coexistence, legal measured/programmed power and absence of kernel panics
during the approved run. Neither a desktop boot nor a build success satisfies
these criteria. Do not record any of these as passed without actual evidence.
