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


## Implementation gap versus this contract — 2026-11-12

The production `SimpleATH` to Tahoe interface implements scan generation
identity and bounded event retention, but **not** the ideal acknowledgement
boundary in step 5. `notifyWirelessScanFinished` sees a pending bridge ticket,
calls a `void` V5 transport notification when an observer exists, and then
acknowledges the ticket even if no observer was registered or a saturated
mailbox dropped the notification. The native InfraProtocol publishes the
WCL `SCAN_DONE` event only later during its poll. This is a known delivery
gap, not evidence that WCL received a completion. Portable tests confirm
identity and ring policy only.

Future source work must preserve the exact epoch/generation through an
acknowledged, failure-reporting mailbox handoff and OS completion delivery.
Retries require a bounded lifetime, explicit stop/epoch cancellation and a
single-direction locking model; the native mailbox callback cannot reenter
the physical provider gate. Native OS publication failure must remain
observable without replaying a stale scan as a successor completion. That
work remains open pending a testable native callback/OS event contract.
