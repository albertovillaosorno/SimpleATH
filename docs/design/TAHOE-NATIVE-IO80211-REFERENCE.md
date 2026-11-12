# External native AirPort precedent for Tahoe — source research only

Earlier sections preserve the historical ABI research snapshots. The latest
production source status is recorded in the concrete native packet-path and
version-2 join/card-inventory sections below.

The third-party AirportRtw88 project reports real native
IO80211 scanning, WPA2 association, DHCP, IPv4/IPv6 and macOS Wi-Fi menu
on Intel Tahoe 26.6.2 build 25G83 with RTL8821CE PCI 10ec:c821.
This is a reference for architectural feasibility, NOT AR9565 validation.

References (read online, never copied into SimpleATH):
- https://github.com/FolKc9/AirportRtw88
- https://github.com/FolKc9/AirportRtw88
- https://github.com/FolKc9/AirportRtw88
- https://github.com/FolKc9/AirportRtw88
- https://github.com/FolKc9/AirportRtw88
- https://github.com/FranciumOS-org/AirPort_RTW89

## Relevant path

A plausible native integration follows the Ventura-style
IO80211Controller and IO80211Interface ABI and the restored Tahoe
IO80211FamilyLegacy and IOSkywalkFamily components, rather than treating
Ethernet as native Wi-Fi or blending incompatible private Skywalk variants.
AirportRtw88's published legacy Info.plist explicitly depends on
IO80211FamilyLegacy 1200.12.2b1, IONetworkingFamily, IOPCIFamily and BSD/KPI
libraries. Its own native attachment/Apple80211 request logic is separate
from its Realtek hardware, just as SimpleATH's AR9565 hardware must be.

Native control-plane requirements include real SCAN_REQ, SCAN_RESULT
enumeration, SCAN_DONE lifecycle, SSID/BSSID/channel, RSSI/noise, auth type,
association state, power on/off, disconnect, interface packet ownership and
real IP traffic. Legacy Tahoe async event clients may behave differently
from old macOS; do not assume SCAN_DONE alone will be consumed before result
reads. Never report RUN state without a genuine associated radio.

Our source now keeps an allocation-bounded scan cache with SSID, BSSID,
channel, advertised rate codes, full verified RSN IE, capabilities, signal
and HT metadata. LegacyScanBridge provides a stable completed scan snapshot
that can remain visible during a later ongoing radio scan, without returning
pointers into DMA or a live mutable cache.

This was initially only a portable result model. The later implementation
sections below supersede that initial snapshot: concrete modern native
controller, InfraProtocol, packet queues, scan and join callers now exist.
Physical RF activation and complete platform integration remain open.

## Exact 25G332 control-path evidence and source integration gates

The pinned `docs/evidence/TAHOE-25G332-KDK-SYMBOLS.json` contains global
**nlist definition candidates** in the matching `IO80211Family` x86_64 image
(UUID `4C2B4969-2B92-3646-9512-C1769BE0F9A4`). An offline exact-key lookup
confirmed the following 11 candidates in that record. It reports
`nativeWirelessAbiVerified=false` and no export trie. **A global definition is
not proof of external link eligibility, callable virtual ABI or availability
in the owner's loaded Tahoe collections.** The declarations below are
mangled-name interpretations, not implementation-ready prototypes.


- **Source-side operation needed:** Register a real wireless interface
  - **Observed exact-build candidate:**
    `IO80211Controller::attachInterface(OSObject*, IOService*)`
  - **Required verification before use:** Superclass layout, virtual slots,
    caller/returned ownership and target-family dependencies. Do **not**
    substitute legacy `attachInterface(IONetworkInterface**, bool)`

- **Source-side operation needed:** Bring up interface identity
  - **Observed exact-build candidate:**
    `IO80211SkywalkInterface::init(IOService*, ether_addr*)`
  - **Required verification before use:** MAC input lifetime, object factory,
    superclass initialization and interface publication ordering

- **Source-side operation needed:** Start/finish radio scans
  - **Observed exact-build candidate:**
    `IO80211Controller::scanStarted(scanSource, apple80211_scan_data*)`,
    `scanDone(scanSource, int)`
  - **Required verification before use:** Valid scan-source values, true
    completion timing and event delivery with an active radio/registered
    controller

- **Source-side operation needed:** Start/finish association
  - **Observed exact-build candidate:**
    `IO80211Controller::joinStarted(scanSource, joinStatus)`,
    `joinDone(scanSource, joinStatus)`
  - **Required verification before use:** Exact join status values, key-install
    and network-state ordering; never emit RUN/connected from parser success

- **Source-side operation needed:** Map native scan controls
  - **Observed exact-build candidate:**
    `apple80211setSCAN_REQ(IO80211SkywalkInterface*, apple80211_scan_data*)`,
    `apple80211getSCAN_RESULT(IO80211SkywalkInterface*,
    apple80211_scan_result*)`
  - **Required verification before use:** Concrete request structure layouts,
    in/out buffer ownership, native selector dispatch and synchronous
    enumeration rules

- **Source-side operation needed:** Deliver RX packets
  - **Observed exact-build candidate:**
    `IO80211SkywalkInterface::inputPacket(IO80211NetworkPacket*,
    packet_info_tag*, ether_header*, bool*, bool)`
  - **Required verification before use:** Actual packet allocator, queue
    context, length/headroom, handoff ownership, teardown, failure-release
    semantics

- **Source-side operation needed:** Handle user/power lifetime
  - **Observed exact-build candidate:**
    `IO80211SkywalkInterface::newUserClient(task_t, void*, uint32_t,
    OSDictionary*, IOUserClient**)`, `setPowerState(unsigned long, IOService*)`
  - **Required verification before use:** User-client entitlements, async
    callback serialization, gate/sleep interactions and outstanding
    packet/control requests


For exact-symbol lookup, the source evidence includes the mangled identifiers
`__ZN17IO80211Controller15attachInterfaceEP8OSObjectP9IOService`,
`__ZN17IO80211Controller8scanDoneE10scanSourcei`,
`__ZN23IO80211SkywalkInterface4initEP9IOServiceP10ether_addr`, and
See the pinned ABI/source value in the evidence index.
These examples provide testable lookup anchors, **not** calls to import into
the current passive kext target. The separate
[25G332 KDK evidence](TAHOE-25G332-KDK.md) records the inactive target
membership and missing native dependency declarations.

The proposed adapter must serialize this progression through a single verified
native owner: exclusive PCI ownership and actual radio initialization;
scan request; bounded `ScanCache`/`LegacyScanBridge` snapshots; radio scan
completion; genuine station association and key installation; then OS link
state and packet delivery. On deauth, radio stop, sleep or provider loss, it
must first quiesce TX/RX and revoke OS packet and user-client callbacks, clear
station/key state and publish disconnection. A borrowed `WifiEngine` RX payload
cannot outlive the DMA buffer; a native packet must own its bytes until the
OS-specific completion/release contract has been established. No readiness
boolean or registered interface may be synthesized from an nlist symbol, a
registry match or the existing source-only state machines.

The **first implementable source unit** should be a bounded scan-control
translation owned by the future native controller: associate each accepted
SCAN_REQ with a monotonically increasing radio/session epoch and requested
scan serial, take only completed copies from `LegacyScanBridge`, expose one
copied result at a time and invalidate all callbacks after stop/sleep/provider
loss. Its portable portion can be host-tested with synthetic beacons and
failed/incomplete scans; it must not manufacture SCAN_DONE or a live interface.
An actual Apple80211 handler must wait for verified 25G332 request/result
sizes, selectors, callback entrypoints and memory ownership. The existing
`LegacyScanBridge` covers only the result snapshot, **not** native dispatch,
radio scanning or OS event delivery. This is the highest-leverage narrow
vertical interface, rather than another disconnected parser or a full mocked
Wi-Fi stack that cannot exercise the unavailable native ABI.

The actual exact-build package exposes `IO80211Family` **1200.13.1** and
`IOSkywalkFamily` **1.0** in its KDK record. The reference Realtek legacy
plist instead requests **`IO80211FamilyLegacy` 1200.12.2b1** on an earlier
Tahoe build. These are different evidence contexts: the KDK record does not
establish that the Realtek legacy family is present, link-eligible or loaded
on stock 25G332. Native family choice and prerequisite availability must be
resolved for the exact target, not inferred from a working patch-based sample.

## Security, controlled port and AWDL ownership decision

An AirPort native interface needs **one** authoritative association/key owner,
not independent macOS and portable handshakes simultaneously. The proposed
source integration boundary (still unverified for the exact native ABI) is:


- **Responsibility:** UI scan, network choice and credentials
  - **Proposed exclusive owner and fail-closed handoff:** macOS AirPort control
    client requests scan/join; controller validates selectors, copies requests,
    and chooses one authorized channel/BSS. Portable `ScanCache` may supply
    verified results but must never invent radio dwell or SCAN_DONE

- **Responsibility:** 802.11 open authentication and association
  - **Proposed exclusive owner and fail-closed handoff:** Native controller
    serializes physical MAC TX/RX and calls `WifiEngine`/`Station` for frame
    parsing/production. OS `joinStarted`/`joinDone` are notifications **after**
    real state transitions, never a parallel second state machine

- **Responsibility:** WPA2-PSK PMK, PTK, GTK, replay and controlled port
  - **Proposed exclusive owner and fail-closed handoff:** Decide which side owns
    4-way handshake **before** enabling adapter. With current source,
    `Wpa2Supplicant` owns derivation/EAPOL state, while a verified native key
    backend alone installs hardware keys and validates PN/MIC. If the selected
    Tahoe Apple80211 contract instead delegates PMK/PTK to the OS and delivers
    `CIPHER_KEY`, do **not** run the portable handshake in parallel; adapt to
    the OS-owned protocol and disable conflicting transitions. The implemented
    modern WCL path now uses driver-owned supplication through the version-2
    native owner contract; runtime behavior remains unverified

- **Responsibility:** Network-ready and packet delivery
  - **Proposed exclusive owner and fail-closed handoff:** Open the controlled
    data port only after real association, authorized channel, pairwise/group
    key installation and replay protection. OS-owned packet buffers and network
    stack handle Ethernet-II payload delivery, DHCP, IPv4/IPv6, DNS and TCP; the
    kext does **not** build a parallel IP stack

- **Responsibility:** Disconnect, sleep, new join, teardown
  - **Proposed exclusive owner and fail-closed handoff:** Work-loop owner closes
    the controlled port first, revokes queues/user callbacks, quiesces DMA,
    erases keys/replay state, retires association/scan epochs and then notifies
    OS. Never publish connected state during recovery or after a stale callback


Exact-build KDK nlist candidates include
`apple80211setASSOCIATE(IO80211SkywalkInterface*, apple80211_assoc_data*)`,
`apple80211setCIPHER_KEY(IO80211SkywalkInterface*, apple80211_key*)`,
`apple80211setKEY_RSC(IO80211SkywalkInterface*, apple80211_key*)`,
`apple80211setRSN_IE(IO80211SkywalkInterface*, apple80211_rsn_ie_data*)`,
and `apple80211setSTA_AUTHORIZE(IO80211SkywalkInterface*,
apple80211_sta_authorize_data*)`. Their existence identifies required
**investigation**, not selector direction, usable callback signatures, OS vs
kext PMK ownership, export eligibility or permission to receive clear keys.
The exact request layout, controlled-port behavior, replay-counter origin,
key deletion semantics and `wifid`/controller ownership must be determined
before choosing one of the two security handoffs. Until then never emit a
successful WPA2 join or OS-ready state, and never install a key twice.

The same KDK inventory contains many `apple80211...AWDL...` definition
candidates, but a station-only AR9565 scan/association implementation does
**not** provide AWDL peer discovery, action frames, off-channel scheduling,
synchronized coexistence, multicast service discovery or Continuity support.
The chosen OS native family and hardware adapter must jointly establish
these contracts (and the required Bluetooth/Continuity prerequisites) before
claiming AirDrop. Working DHCP/IP alone is insufficient; availability remains
unverified even if ordinary station networking becomes functional.

Before introducing any `IO80211Controller` subclass into the Xcode Sources
phase, the P0 ABI task must supply exact-target method and virtual signatures,
verified exports/KPI eligibility, object size and superclass constructor
requirements, complete Apple80211 request/event structure layouts and queue
ownership. Only then can implementation add matching family declarations to
`Info.plist` and, when separately authorized, inspect the produced artifact's
actual imports/relocations. Those prerequisites remain **open** here; no
native adapter has been enabled or compiled.

## Compatibility and safety requirements

- Our target: Dell Inspiron 5567 AR9565 (168c:0036), macOS 26.7.2 /
  build 25G332. The reference's validated hardware and OS are different.
- Check exact kernel collection exports, IOPCIFamily, IO80211FamilyLegacy,
  IONetworkingFamily and required reserved symbols against the real Dell.
  No Apple vtable, class size, virtual selector or kernel symbol address
  can be copied from the Realtek controller unverified.
- Restoring legacy Apple Wi-Fi families may require OCLP-specific changes.
  The known bootable USB EFI and SSD must not be modified without renewed
  explicit owner authorization. Do not add a disabled legacy family to an
  active release and call it functional; match the correct stack precisely.
- The external repository contains files licensed GPL-2.0 OR BSD-3-Clause.
  We only inspect it as a reference: no third-party source is copied or
  redistributed. Independently authored SimpleATH code has no project-wide
  license grant; upstream terms remain unchanged.
- Wi-Fi menu integration is a separate macOS integration milestone from
  PCI access, calibrated AR9565 RF, DMA, 802.11 security and real traffic.

No build, tests, kext injection, PCI access, root patch, USB/EFI changes
or on-device experiments were performed for this research.

## Exact 25G332 modern-family layout inspection (2026-11-09)

The matching KDK DMG was fetched to temporary storage, SHA-256 checked against
`9490bd9b5e16ff5cee8b7330c498d64f27a008aa91c5c70d686a00dc5978c555`,
and inspected without mounting, installing or executing its binaries.
The selected IO80211Family image has UUID
`4C2B4969-2B92-3646-9512-C1769BE0F9A4`, matching the existing evidence.

Static metaclass constructors report sizes 0x128 for IO80211Controller and
IO80211SkywalkInterface, 0x130 for IO80211InfraInterface and
IO80211InfraProtocol, and 0x10 for IO80211NoneProtocol. The controller's
modern attachInterface(OSObject*,IOService*) entry is at vtable offset 0xdc8
relative to the first virtual-function entry. NoneProtocol derives from
OSObject; it is not a legacy IO80211Interface substitute.

The exact
`apple80211setSCAN_REQ(IO80211SkywalkInterface*,apple80211_scan_data*)`
wrapper checks the NoneProtocol metaclass and calls offset 0x1b0. Its legacy
scan request path must not be confused with the modern InfraProtocol WCL
scan/association path. The installed compatibility SDK contains legacy and
incomplete Skywalk declarations; its names alone do not establish this ABI.
Native declarations and the corresponding interface/packet/event owner still
need source implementation and link/layout validation before use.

A current native Tahoe reference, AirportMtkWlan at commit
`37aa87eecf9fd2246c0f4ef9879416afa396a105`, independently describes the modern
controller/InfraProtocol/WCL architecture. It was consulted as API research;
its GPLv2 implementation and headers were not copied into the driver.
https://github.com/Arxusion/AirportMtkWlan

## Native work queue and CoreCapture integration — 2026-11-10

`SimpleATHTahoeController` now overrides `createWorkQueue` and `getWorkQueue`
with the native `IO80211WorkQueue::workQueue()` factory. Static inspection of
the exact 25G332 IO80211Family shows the superclass implementations return
false and null, while `createWorkLoop` and `getWorkLoop` delegate to those
virtual slots. The native queue must therefore precede CoreCapture/WCL startup.

The ordinary target now includes `TahoeCapture.cpp`: native factories create
three CoreCapture pipes, a CCLogStream, a CCDataStream, a CCFaultReporter and
the IO80211/CommonFaultReporter wrapper. The callbacks no longer return null
throughout a successful controller lifetime. Pipe outputs remain optional:
25G332 `IO80211Controller::getDriverTextLog()` calls `getLogPipes` with only
the first output supplied. Factory-returned objects retain their real native
OSObject prefix/metaclass; no private CC object is allocated by guessed size.
Partial setup unwinds consumers before streams and pipes, and normal teardown
keeps capture/queue resources alive until native superclass stop completes.

The independently declared factory labels and option offsets were checked
against the KDK's IO80211Family UUID
`4C2B4969-2B92-3646-9512-C1769BE0F9A4` and selected corecapture SHA-256
`8c9900f9a82de85191cfd26db882cdef0a4aeef2e99744d2922c2720cc529651`. The
buffer sizes consumed by native option readers are 0x350 (pipe) and 0x358
(stream). `com.apple.driver.corecapture` 1.0 is a direct bundle dependency.
No Apple executable or headers are copied into the repository.

These are source/ABI observations and real startup calls, not native runtime
validation or completion of the missing InfraProtocol registration, WCL
request/event dispatcher, Skywalk packet ownership and radio activation.
Those requirements remain open. No kext build, load or physical test ran.


## Concrete InfraProtocol and native packet path — 2026-11-10

This source update supersedes earlier statements that no native class is
instantiated. `SimpleATHTahoeController::start` now creates the concrete
`SimpleATHInfraProtocol`, initializes its real native Infra/Skywalk prefix,
sets infrastructure role/id, attaches the IOService and native controller,
starts it and publishes it after native packet registration succeeds. Start
errors unwind child resources before controller capture/work-queue teardown.
Published children are terminated before detachment; event sources are retired
while the controller is alive, even if an OS client retains the stopped child.

`TahoePacketPath` creates actual native IOSkywalkPacketBufferPool objects and
TX-submission/TX-completion/RX-completion queues. Its on-demand RX allocation
uses the kernel pool, not an RX submission buffer provider. The genuine native
`registerInfraEthernetInterface` API performs wireless/BSD registration with
these three queues; its result is IOReturn, zero on success. RegistrationInfo
is a 0x130-byte factory-initialized buffer with option/version 1. No private
expansion pointers or fake IOEthernetInterface provider are written.

The independently imported 19 native method labels were checked as defined
external nlist symbols (n_type 0x0f) in matching 25G332 IO80211Family and
IOSkywalkFamily. This is static evidence, not a loaded-kernel link/runtime
claim. Queue action callbacks return packet counts, not IOReturn: native
legacyDequeue advances only by accepted TX count; enqueueAndCompletePackets
uses the completion callback's produced count. Native networking TX refill
prepares packets before submission. Accepted Ethernet bytes are copied into
the radio owner before OS completion; retained packets return through native
TX completion exactly once. RX owns new pool storage and completes/returns
unused prepared packets. Queue pressure leaves unaccepted TX packets with
Skywalk. All callbacks share the controller's native work loop.

A second ABI correction is `getSelfMacAddr`: native registration masks the
returned RAX value to six MAC bytes. It returns the address value, not a
pointer. The concrete override follows that contract. Queue/pool accessors
and deferBSDAttach are typed at their existing virtual slots.

Modern WCL scan requests now enter an interface command gate and the physical
owner's real generation-scoped scan operation. The copied completion path
filters SSID/BSSID/2.4 GHz channels, encodes observed BSS snapshots and posts
native scan-result/scan-done messages. It never invents a radio dwell or scan
success. The current physical owner only has a verified-current-channel
passive dwell path; channel traversal and active probing remain required RF
work. The scan request identifier is not mistaken for a version. Inventory,
MAC, channel, signal, power, leave/abort and data-path requests reach real
provider operations; the controller does not globally prohibit inventory or
power requests just because the radio is currently down.

Focused evidence: the three changed native translation units pass strict
Darwin SDK C++14 syntax-only checking; the production-used scan codec passes
its offline host fixture for truncated requests, 5/6 GHz overlap, SSID filters,
maximum rate/RSN payload capacity and malformed RSN rejection. No kext
compilation, link, load, radio or physical traffic test has run. Source/global
lint is not claimed clean. The subsequent version-2 join and capability
implementation below supersedes
the previous missing-control-path snapshot. RF activation, remaining required
selectors, Bluetooth-host integration and AWDL still prevent a 100% source or
notebook-readiness claim.

## Version-2 native join and capability inventory — 2026-11-10

The production WCL associate slot now decodes the fixed 0x2cc native request,
including exact BSSID/SSID/channel and either a supplied PMK or bounded
passphrase-to-PMK derivation. `NativeConnectRequest` carries a provider epoch,
monotonic request ID and an owned 32-byte PMK. `SimpleATHWirelessOwnerV3`
originally negotiated this changed shape explicitly (later superseded by V4
for association-scoped port authorization). Transport and physical provider
make short-lived copies and erase them after their gates return. The provider
uses the driver-owned `WifiEngine` open/WPA2 selection paths; a macOS-owned
four-way handshake is no longer assumed for this modern request.

`JoinSession` runs in the actual InfraProtocol polling path. It matches the
provider epoch, request ID, exact BSSID and successful association generation.
Association, first freshly observed associated beacon, real controlled-port
opening and connection completion are distinct observations. Parser success,
a queued authentication frame or a supplied PMK cannot emit connected state.
Abort/leave, timeout, provider loss and successor generations retire the old
session. `getWCL_BSS_INFO` encodes the provider's copied associated BSS; RSSI
requires a genuine current-association signal measurement.

The source used the retained BE200 WCL files for protocol research, then
checked the following facts directly in matching 25G332 IO80211Family (UUID
`4C2B4969-2B92-3646-9512-C1769BE0F9A4`). These are static ABI observations,
not loaded-kernel validation, and no implementation bodies were imported.


- **Native consumer:** `WCLJoinManager::authAssocCompleteEventHandler`, 0xf47aa
  - **Observed requirement:** Exact 0x1c event extent

- **Native consumer:** `WCLJoinManager::firstBeaconEventHandler`, 0xf4832
  - **Observed requirement:** Exact 0x14 event extent

- **Native consumer:** `WCLJoinManager::connectCompleteEventHandler`, 0xf48b4
  - **Observed requirement:** Exact 0xa4 event extent

- **Native consumer:** `WCLJoinRequest::updateFirstBeaconEvent`, 0x11ea12
  - **Observed requirement:** BSSID at byte 4, driver status/reason at byte 12,
    status/reason at bytes 0/2

- **Native consumer:** `WCLJoinRequest::updateConnectCompleteEvent`, 0x11eb0c
  - **Observed requirement:** First peer driver status/reason at byte 12,
    status/reason at bytes 0/2

- **Native consumer:** `WCLNetManager::handleSupplicantEvent`, 0xec12
  - **Observed requirement:** Exact 0x28 event; `updateSupplicantEvent` reads
    status at byte 8

- **Native consumer:** `WCLNetManager::linkStatusInd`, 0xd77c
  - **Observed requirement:** Link-up byte at offset 6

- **Native consumer:** `WCLDeviceConfiguration::setCardCapbilities`, 0xf04fc
  - **Observed requirement:** Copies three qwords and one dword: 0x1c bytes
    total

- **Native consumer:** `WCLDeviceConfiguration::getCardCapbilities`, 0xf0534
  - **Observed requirement:** Stored envelope begins at object-data offset 0xc98

- **Native consumer:** `is6GSupported`, `isHeSupported`, `isEhtSupported`
  - **Observed requirement:** Bitmap byte 11 bit 6, byte 17 bit 7, byte 17 bit
    4, respectively


The controller's card-capability getter now supplies that complete modern
28-byte envelope instead of always returning Unsupported or copying the
compatibility SDK's smaller legacy 16-byte structure. It describes CCMP,
WPA2, short slot/preamble and the implemented asynchronous scan/completion
contract. It does not imply radio readiness, advertise unrelated PHY bands,
or turn the still-missing native AWDL service into a claimed capability.
Inventory remains queryable before RF startup and while the radio is off.
The exact bitmap and padding are represented by `TahoeCapabilities.hpp` in
the normal production controller; there is no experimental opt-in path.

The capability fixture verifies the independent native extent, wire offsets,
required bits, zeroed later feature/padding bytes and neighboring sentinels.
Its host run and strict SDK C++14 controller syntax pass. Existing join
lifecycle/wire fixtures passed C++14/C++17 ASan/UBSan. These focused checks do
not establish global lint success, native linking, packet registration or
physical traffic. Required RF/country/coexistence orchestration, complete
native packet/CCMP operation, Bluetooth host and AirDrop/AWDL remain open.

## Native single-chain and power-save query wiring — 2026-11-10

`SimpleATHInfraProtocol::requestGated` now implements the Tahoe WCL
`getNSS` (slot `0x0fe0`) and `getPOWERSAVE` (slot `0x0eb0`) handlers instead
of falling through to Unsupported. The responses are based on fixed hardware
and software facts: AR9565/PCI `168c:0036` supports **one** spatial stream,
and SimpleATH does **not yet** implement 802.11 beacon/TIM/DTIM radio doze,
so its power-save level is explicitly Disabled. They are independent of
association and remain queryable before radio startup; neither is a positive
radio-power, active link, country authorization or transmit-ready assertion.

The source uses full zero-initialized eight-byte envelopes, including the
three padding bytes after the NSS octet. Static assertions compare these
layouts to the retained MacKernelSDK `apple80211_nss_data` and
`apple80211_powersave_data` definitions and verify
`APPLE80211_VERSION`/Disabled constants. Public AirportItlwm getters were
consulted as API examples, not copied into this implementation; their pinned
revisions and exact source hashes are recorded in `.references/ledger.jsonl`.
The existing independently inspected Tahoe slot ordering remains the source
for the two virtual selectors. Exact device/runtime behavior on the loaded
25G332 family is still unverified; local SDK layout assertions are not ABI
linkage or a kext build.

`tests/test_tahoe_capabilities.cpp` now exercises both new envelopes, exact
wire offsets, their declared lengths, zeroed NSS reserved bytes and trailing
canaries, in addition to the existing 28-byte card capability inventory.
Focused C++14 and C++17 ASan/UBSan host fixtures, native MacKernelSDK C++14
syntax and strict test-unit Tidy passed. The larger preexisting
`SimpleATHInfraProtocol.cpp` Tidy backlog remains unresolved, and full
CI/kernel operation is not established. The actual RF/channel calibration,
real 802.11 power save, supported regulatory channels and AWDL/Bluetooth
coexistence remain separate P0 implementation work.

## Epoch-bound native receive callbacks — 2026-11-10

The physical PCI owner and Tahoe wireless transport now negotiate the internal
`SimpleATHWirelessOwnerV3` provider function and version 3 callback table
(at the time; subsequently superseded by V4).
A copied Ethernet receive callback carries both the physical-owner epoch and
association generation. The transport checks both against its most recently
verified live snapshot under the mailbox lock *before* accepting payload bytes.
Old-generation or premature next-generation callbacks are dropped, including
old associations on the same PCI epoch. A changed association invalidates
queued packets before a new session can be authorized. Only the existing
serialized `RadioChanged`/`ProviderStopped` notification or an explicit live
snapshot can advance the consumer epoch and association identity. Provider
termination
revokes all callbacks. This prevents a delayed old-epoch Ethernet/EAPOL frame
from being relabeled with a freshly associated epoch merely because the
consumer mailbox is open. Provider-unsubscribe still joins callbacks before
releasing mailbox storage; this change does not manufacture physical RX or
native Wi-Fi readiness.

The portable `tests/test_native_wireless_epoch.cpp` covers zero and matching
epochs, stale/premature PCI and association
generations, terminal epochs and stopped providers. Native source and
exact-target linking still require validation
on an authorized macOS build; this test is a host policy check only.

An additional notification revision is captured before each provider snapshot.
If a callback arrives before the snapshot is published, or the sampled PCI
epoch is older than the consumer's active epoch, the transport rejects that
snapshot instead of rolling back its association or RF authorization. The
revision never wraps into a potentially trusted value; exhausting it revokes
the transport. The host fixture covers both stale-epoch and intervening-event
snapshot rejection; physical execution remains unverified.

## Scoped physical controlled-port requests — 2026-11-10

`WirelessOwnerV4` replaces the prior unscoped `authorizePort(bool)` callback
with `NativePortRequest { epoch, joinRequestId, associationGeneration, open }`.
The Tahoe native transport takes one verified provider snapshot before
submitting the command; the PCI provider checks all three identity fields
*inside its own serialized IOCommandGate* before opening or closing a port.
After a successful open, the transport rechecks the same identity and
controlled-port state. If this confirmation fails, it may revoke only the
*original* association; its rollback cannot close a replacement join in the
same PCI epoch. Existing internal security predicates (verified protected RX,
WPA2 M4 TX, keycache, RF kill and channel/queue admission) are unchanged.

The portable epoch fixture now checks same-epoch association replacement,
join request replacement, PCI epoch changes, zero and maximum 64-bit
identities. Native source syntax and portable sanitizer tests are source-only
checks; they do not constitute a physical RF/Wi-Fi test or proof of Tahoe ABI
runtime compatibility. The older V3 records above describe their historical
implementation, now superseded by V4.


## Native scan-generation callback — 2026-11-12

`WirelessOwnerV5` supersedes the internal V4 provider callback signature;
`SimpleATHWirelessOwnerV5` has an explicit distinct lookup identifier and
ABI number 5. The callback now carries a fourth `generation` argument,
nonzero only for `ScanFinished`. The PCI provider emits the bridge completion
ticket's generation, not the independent WifiEngine dwell generation. The
transport stores the ticket with the epoch in its bounded event ring, and the
InfraProtocol compares it against the *current* WCL scan generation before
consuming results. A matching PCI epoch and finished radio dwell alone were
insufficient to reject a queued old completion after a new scan finished.
The previous V4 controlled-port semantics are retained unchanged.

This is an internal owner-to-controller source contract, not an assertion
about Apple's private Tahoe 25G332 layout or permitted kernel imports. No
hardware scan, WCL callback, kext load or physical RF was exercised.


A full mailbox first evicts a noncritical notification. If all slots are
terminal, a newer `ScanFinished` may instead evict a *different* older scan
generation, whose native WCL request is already superseded. It cannot evict
`ProviderStopped`, a duplicate, or a newer generation. Portable tests
check wraparound, preserved ordering and invalid eviction inputs; this does
not prove a viable native Tahoe event consumer or guarantee delivery under
indefinite callback starvation.


A full mailbox first evicts a noncritical notification. If all slots are
terminal, a newer `ScanFinished` may instead evict a *different* older scan
generation, whose native WCL request is already superseded. It cannot evict
`ProviderStopped`, a duplicate, or a newer generation. Portable tests
check wraparound, preserved ordering and invalid eviction inputs; this does
not prove a viable native Tahoe event consumer or guarantee delivery under
indefinite callback starvation.


The provider's `notifyWirelessScanFinished` currently acknowledges a bridge
ticket after attempting the `void` V5 callback, without knowing whether the
transport enqueued it. `TahoeWirelessTransport::notify` may reject a full
event ring, and `SimpleATHInfraProtocol::finishScan` publishes the OS event
only on a subsequent poll. The portable bridge's stronger requirement of
acknowledgement after OS completion dispatch is therefore not met by this
source integration. An explicit result-bearing callback, bounded retry and
cross-workloop acknowledgement need a deadlock-free contract and proof of
identity before this path can be considered reliable. See the open native
Tahoe AirPort task; no physical/OS outcome is implied here.
