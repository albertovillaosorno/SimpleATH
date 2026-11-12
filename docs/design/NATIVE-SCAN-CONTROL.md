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
