# Controller-owned scan lifecycle contract — portable source only

Status: staged source boundary, **not a native Apple80211 adapter**, not a
physical AR9565 scan or a Tahoe ABI approval. No hardware, EFI, kext build,
OS Wi-Fi registration or kernel event was invoked. The compiled native driver
remains passive; all readiness and runtime capability gates stay false.

## Falsifiable path and trust boundary

1. A future controlling `IOService` must own the verified physical PCI function,
   serialized power state, country/channel policy, RF channel dwell and a live
   RX ring. Only its genuine FCS/DMA-verified beacon or probe-response bytes
   may enter `ScanCache::observe`. A source-only test may supply synthetic
   frames but must not claim those provenance requirements are satisfied.
2. On a real `SCAN_REQ`, that owner accepts an explicit request serial and calls
   `LegacyScanBridge::beginScan(serial, ticket)` under its work-loop gate.
   The bridge creates a monotonic generation token for logical replay
   protection; it is not a cryptographic authenticity mechanism. The radio
   worker keeps this exact ticket. Request serials cannot repeat during the
   current lifetime unless `clear()` retires the old owner epoch.
3. Only after actual RF dwell and its RX processing is finished may the worker
   call `completeScan(cache, ticket, succeeded)`. A stale, repeated,
   wrong-serial
   or previous-epoch completion returns `InvalidState` without mutating the
   current request. `clear()` removes all scan entries and pending events but
   does **not** reset the generation source. On a 64-bit generation exhaust,
   new requests fail instead of wrapping and accepting stale completions.
4. A successful completion snapshots bounded BSS records and retains verified
   SSID/BSSID/channel/RSN/rates/signal metadata as values. `next` iterates only
   this completed snapshot only with its matching completion ticket, which
   survives a subsequent in-progress scan. `rewind` has the same ticket gate;
   a stale callback from a retired controller cannot disturb newer results. No
   output points into DMA buffers or mutable cache entries. Failure does not
   manufacture a new completed result.
5. `completion(out)` exposes a pending **event intent** containing the matching
   serial/generation, success flag and result count. Failed radio work and
   malformed caches produce a failed event intent, not a fake successful
   scan. Another `beginScan` returns `EventPending` until the native owner has
   truly dispatched the matching OS completion notification and called
   `acknowledgeCompletion(ticket)`. A stale acknowledgement cannot drain a
   newer event. This portable code makes **no** calls to `scanDone`, issues
   no Apple80211 requests and has no authority to mark a real scan complete.

The underlying serialized owner is responsible for cancellation on stop,
termination, RF-kill, sleep and power loss. It must call `clear()` and
invalidate
its real radio work before reopening scan requests. The bridge is intentionally
not thread-safe: callbacks, cache snapshots, iterator and event acknowledgements
must share one gate. Native event dispatch failure leaves intent pending so the
controller can retry or terminate cleanly. A pending completion is not proof
that macOS has consumed a scan event.

## Exact Tahoe ABI evidence required before a native dispatcher

The pinned **25G332** KDK contains candidate IO80211Controller symbols, but
symbol names and DWARF declarations alone do not prove eligible KPI imports,
callable method slots or a usable Skywalk interface. The owner must validate
against the exact target build: class/superclass and vtable layout, methods
for scan request, scan result and scan started/completed notifications, actual
Apple80211 request selectors and structures (including ownership/lifetimes),
legacy family dependencies and the event-consumer contract. See
`TAHOE-25G332-KDK.md`, `TAHOE-NATIVE-IO80211-REFERENCE.md` and
`ABI-EVIDENCE-ACQUISITION.md`. Public Realtek Tahoe precedent targets another
card/build and a restored legacy family; it is not evidence of AR9565 support.

A source-only regression must prove success and failure event intents, stale
completion and stale acknowledgement after stop/reset, repeated request serial
with different generation, invalid cache rejection, and stable previous
snapshot while new scan runs. Such tests are synthetic contracts, never a
native callback, radio readiness, physical RF or IP connectivity result.


## Native acknowledgement wiring and remaining gap — 2026-11-12

The internal `SimpleATHWirelessOwnerV7` callback retains the V6 `IOReturn`
from the bounded mailbox, instead of treating a `void` callback as delivery.
The PCI owner holds the bridge completion intent until the matching native
InfraProtocol calls `acknowledgeScanCompletion(epoch, generation)` **after**
calling the OS `SCAN_DONE` event API. Retry is initiated by the native poll,
no more than once per poll while the original scan is finished and still
owned by the same PCI epoch. A full mailbox returns `NoResources`; the
bridge remains pending, preventing a successor scan from reusing the event.
A successful handoff is remembered by generation so retries cannot enqueue a
duplicate. Stop/reset retires the intent and the subscription, and both the
provider and transport reject stale acknowledgements. If WCL cancels after
a temporarily unreadable radio snapshot, the native owner attempts physical
cancellation before posting the abort. If the bridge completion has not yet
arrived, the consumer remembers the exact epoch/generation and reconciles
it after the worker finishes. The same identity retry applies when a normal
`SCAN_DONE` is posted but its provider acknowledgement fails; otherwise the
bridge can remain `EventPending` and block later scans. Only the matching
bridge intent may be retired, never a successor generation.

An interrupted scan on a still-live PCI epoch must preserve its failed
completion intent even when RF-kill, link retirement or queue loss makes the
receiver unsafe.
Its old BSS enumeration lease is revoked and future result reads check live
RF/channel/queue readiness, but the terminal event and its
successful-handoff deduplication marker remain until the native consumer
acknowledges the exact ticket. Stop/reset and observer handover may explicitly
retire the whole epoch/observer intent instead. Clearing the bridge immediately
after queueing a failure event loses its acknowledgement target and risks
advancing another scan before WCL sees completion.

A provider unsubscribe remains independent of the PCI gate so callbacks can
join safely even after the work loop has been removed. The *next* subscriber,
under the live owner's serialized gate, cancels any former observer's physical
scan and clears its old bridge ticket, completion and deduplication identity
before publishing the replacement callback. Without this handover an old
unacknowledged `EventPending` completion could permanently block the new
consumer, which has no previous scan request to acknowledge. The new native
observer must initiate a fresh scan; it is never sent a fabricated old event.
The callback takes only an observer lock and the transport mailbox lock;
no provider callback enters the child's work-loop gate. The child drops its
mailbox lock before calling the provider acknowledgement gate.

A V7 `NativeScanStartRequest` also carries the caller's sampled PCI epoch
into the provider's serialized command gate. A mismatched epoch fails before
creating a physical dwell or bridge ticket. On success, the owner returns both
its accepted epoch and bridge generation from that same gated operation; the
transport checks both under the mailbox lock before exposing them to WCL.
This closes the reset-between-snapshot-and-start race without starting an
orphan scan. Any subsequent reset still requires normal owner retirement.

**This is not evidence that macOS consumed the notification.** The native
`wirelessPost` OS event wrapper currently returns `void`, so the source can
only prove that its invocation precedes acknowledgement; it cannot observe
a delivery failure downstream of that call. Further exact-Tahoe ABI
verification, a result-bearing OS publication contract where available, and
runtime inspection remain open. Synthetic source-wiring and portable
ring-policy checks are not a macOS callback or physical RF test.

## Native control-plane poll scheduler loss (2026-11-12)

The native InfraProtocol work-loop uses a periodic real IOTimerEventSource
for WCL scan completion/acknowledgement, join and beacon state, association
link-down, and Skywalk packet serving. A failed initial timer arm now aborts
interface startup; a failed subsequent re-arm shuts down that interface
instead of leaving an OS-visible link and packet service without a bounded
control-plane observer. Shutdown sends a link-down and radio-unavailable
notification only if they were previously advertised, cancels an active scan,
retires the join and stops native packet resources. Both timer failures
also request an actual radio shutdown through the exclusive PCI owner, with
a separately recorded error if physical DMA release cannot be confirmed.
It does not assume the OS consumed those events, nor does it imply physical
RF authorization or that a failed shutdown was successful.
Offline source checks guard both timer sites and notification ordering;
testing actual event source failures still requires an authorized Tahoe SDK.

## Same-epoch Skywalk data enable revocation (2026-11-12)

An explicit WCL leave now revokes the old `dataRequested_` and
`dataRequestEpoch_` lease before calling the physical PCI owner's station
leave function. Even if the provider reports Busy or another failure, the
next poll cannot re-enable an older controlled-port Skywalk queue. Native
join retirement, including observed AP disconnection, failure and timeout,
also clears that demand before stopping the packet queue. A fresh OS packet
enable is required to resume service after that association's retirement;
the initial pre-association enable remains available for a fresh first join.
The provider continues to enforce its independent association/key/RF gates.
Source-only regressions cover the call ordering; no live AirPort leave or
successful new association has been demonstrated.

## Retired native interface status admission (2026-11-12)

The synchronous chip-ready, association and link-state getters now require
the InfraProtocol interface to remain active before sampling the physical
provider. A failed poll timer retires that interface even if the separate
`radioPower(false)` call fails. Its getters must then return unavailable,
station initialization and link down respectively; a positive or stale owner
snapshot cannot restore a stopped WCL interface. This is an offline
source-level guard, not evidence that Tahoe has consumed a state event or
that physical RF shutdown succeeded.

## Native WCL association result consistency (2026-11-12)

The portable `JoinSession` now treats any nonzero provider join status as
terminal even if a phase snapshot still says Handshaking or Ready. It cannot
produce association, supplicant, beacon or connection success notices from
that inconsistent observation; a previously connected join emits its one
disconnection intent instead. Portable tests exercise failed status before
association and after an established join, with no real Tahoe callbacks.

## Native transport RX revocation on failed snapshots (2026-11-12)

If a serialized physical-provider snapshot fails or reports a zero PCI
epoch, the Tahoe transport now clears its cached ordinary-data and EAPOL
receive leases, association-generation identity and all queued received
Ethernet bytes while holding the mailbox lock. It cannot deliver packets
from the prior associated AP merely because no radio-change event arrived.
Pending scan results, OS event intents and provider completion tickets are
left alone for their separate identity-scoped acknowledgement or retirement.
Only a later successful live provider snapshot can reauthorize reception.
This is source-wiring regression evidence, not tested macOS packet delivery.

## Skywalk completion ownership on native link disable (2026-11-12)

The packet path now drains retained, already-accepted Skywalk TX packets
through its native completion queue at ordinary link/packet disable, not
only at final interface stop. Disabling its event source also disables
the completion-request poll; without this drain, accepted OS packet
objects could remain retained through repeated offline/online cycles.
The physical owner has already copied accepted TX bytes and remains
responsible for descriptor completion and radio isolation. The drain is
bounded by the fixed queue capacity and is idempotent on repeated disable
or final stop. Offline source assertions cover the call and completion
path; no kernel Skywalk queue behavior has been verified.

## Native WCL link event authorization (2026-11-12)

The periodic InfraProtocol AirPort link-up notification now requires an
active, fully connected native WCL join session as well as the physical
provider's authorized associated, controlled-port and beacon evidence. A
failed join status, explicit leave or terminal RF event can invalidate the
local WCL identity before stale provider data is projected as OS link-up.
The getter that reports physical 802.11 association remains distinct from
this WCL link-up notification. No live Tahoe UI or physical association
transition was observed in these offline wiring checks.

## Native receive quarantine after a failed power-off (2026-11-12)

The transport now latches an explicit OS power-off request before entering the
physical PCI owner's stop callback. Whether that callback succeeds or fails,
ordinary Ethernet and EAPOL receive authorization, association identity and
queued receive bytes are immediately revoked. A failed stop preserves event
and scan completion tickets for their own acknowledgement; it does not prove
physical DMA was quiesced. A stale positive owner snapshot cannot regrant
receive authorization or publish radio availability while the off-intent
latch remains set. Only a successful power-on callback or a fresh bind clears
that local latch, after which a new validated snapshot establishes live state.
This protects native mailbox admission, not hardware safety or actual power-off
on macOS. Offline source-wiring checks cover ordering and the recovery gate.

## Native poll event-before-status ordering (2026-11-12)

A provider radio, association, link or terminal-stop notification may race the
native InfraProtocol timer's sampled owner state. The timer now drains a bounded
batch of mailbox events and requests a fresh provider snapshot after observing
such a state-changing notification, before it emits a positive WCL join, AirPort
link, radio availability or enables Skywalk packets. A refresh failure is
interpreted as unavailable; scan completion identities survive the drain and
are still accepted only for the current epoch/generation after physical scan
termination is confirmed. A previously rejected scan-completion handoff is
retried before draining, so a newly accepted completion can finish in the
same poll. The work-loop is serialized, but a new hardware callback can still
arrive after this second snapshot; physical owner gates and future polling
must independently reject stale work. Offline policy and wiring regressions
cover the transition order; no actual OS callback timing was measured.

The refreshed state also aborts a still-pending WCL scan when RF power,
radio availability or RF-kill admission is lost *without* a PCI epoch change.
The owner receives a best-effort physical cancel first, then the local scan
emits an aborted completion rather than treating an old completion event as
successful for a radio that is no longer available. Failed scan completion
acknowledgement retains its existing identity-scoped retry.

## Failed native WCL leave retirement (2026-11-12)

An explicit WCL leave or abort request now retires the local join identity
and Skywalk demand even when the physical station-leave callback rejects the
operation. A failed physical disassociation still returns its original error
and does not claim the RF or DMA was stopped. Previously, the locally active
join survived a failed owner leave: a later still-associated, port-open
provider snapshot could reannounce the OS link despite the user requesting
leave. Terminal connection and link-down notices now follow `retireJoin`'s
one-shot session lifecycle; a failed abort does not synthesize a successful
abort event. This is an offline source-order regression, not a Tahoe WCL test.

## Native WCL station identity after MAC override — 2026-11-12

The physical snapshot distinguishes EEPROM `permanentMac` from readback-
confirmed PCU `currentMac`. Native `getHardwareAddress` already returns the
current address, but the `getHW_ADDR` WCL selector previously returned the
permanent address. After a permitted quiesced locally administered override,
these two OS entrypoints would disagree with the PCU and the management-frame
source address. Both now expose `currentMac` from the same owner snapshot;
`permanentMac` remains available as a separate immutable board fact. The
owner rejects snapshots until station MAC programming has been verified.
Source wiring tests confirm equality of the two reporting paths, not runtime
Tahoe ABI behavior or hardware verification.

## Null-payload WCL scan cancellation — 2026-11-12

The `setWCL_SCAN_ABORT` selector needs no request payload. Its prior dispatch
position, below the common null-data check, rejected a payloadless abort
with `BadArgument` before reaching the physical scan owner's cancellation.
It now follows leave/join-abort in the null-safe branch, invokes the exact
active bridge generation and publishes local `SCAN_DONE` only when the owner
accepted cancellation. A missing generation still returns `NotFound`; a
failed provider cancel is returned without inventing an OS completion. A
source-order regression covers this boundary; Tahoe event delivery remains
unverified without kernel execution.

## WCL status is bound to an accepted join identity — 2026-11-12

A physical owner's positive association snapshot does not establish that the
local WCL join token is still accepted. In particular, an explicit leave,
join failure or stale same-epoch AP observation can outlive its AirPort
session. `getAssocState`, `linkState` and the periodic link-up notification
now require the accepted local join to be connected to exactly the observed
PCI epoch, join request, association generation, BSSID, port and beacon. The
OS getters enter the InfraProtocol's command gate before inspecting its
mutable join token; failed gate or provider reads remain down. The pure
C++14/17 join fixture rejects every stale identity independently. These
source contracts do not prove Tahoe work-loop reentrancy or kernel behavior.
