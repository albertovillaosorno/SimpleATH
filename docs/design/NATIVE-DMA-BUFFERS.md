# Native DMA packet buffers — disabled, uncompiled source

`src/platform/Ar9565NativeDma.*` implements a packet-buffer resource path using
IOBufferMemoryDescriptor, a device-specific IOMapper and IODMACommand. It is
included in the Xcode target, behind
`SIMPLEATH_ENABLE_EXPERIMENTAL_DMA_BACKEND=0`. No passive service instantiates
it. No build, test suite, mapping, hardware transfer or buffer completion has
been performed. This is not a working DMA queue, descriptor ring or Wi-Fi path.

## Why allocation is separate from hardware ownership

The pinned [IODMACommand header](https://github.com/acidanthera/MacKernelSDK/blob/3f750085caa17ec3a7880f11c11bf4f48cd6a164/Headers/IOKit/IODMACommand.h)
documents that prepare can block and must not run while gated. The
[buffer allocator](https://github.com/acidanthera/MacKernelSDK/blob/3f750085caa17ec3a7880f11c11bf4f48cd6a164/Headers/IOKit/IOBufferMemoryDescriptor.h)
can also block. Serializing every DMA call inside IOCommandGate would violate
that contract. The controller must implement this ownership transfer:

1. Under its gate, reserve a unique nonzero allocation ID in the current
   nonzero powered-session epoch and retain an outstanding-operation reference.
   IDs must never wrap/reuse during a controller lifetime. The PCI function
   must already be exclusively owned, with physical identity established.
2. A separate sleepable client thread prepares a private NativeDmaBuffer.
   The client owns that object exclusively until allocation completes.
   Retaining provider/work-loop objects prevents their deallocation; it does
   not prevent provider termination, sleep or epoch invalidation.
3. Reenter the gate with the **current** owner epoch. publishGated rejects a
   mismatch, returns no addresses, and leaves the unpublished mapping eligible
   for client-context release. This handles sleep/stop during a blocking prepare.
4. Publication assigns a nonwrapping per-buffer submission serial and marks
   the buffer DeviceOwned **before** the controller can program hardware. The
   output contains only OS-generated I/O bus segments and an epoch/allocation/
   submission token. Distinct buffers require distinct allocation IDs.
5. On genuine completion, or verified engine quiescence/reset/isolation, the
   gate retires the matching token. An IRQ mask or timeout is not proof.
   HardwareQuiesced retirement permits cleanup but does not make an RX payload
   readable as a completed packet. A stale token cannot retire a newer transfer.
6. Transfer CPU ownership to the client thread for RX copying, reuse or release.
   The controller must drain outstanding client work before destroying its
   context; gated and client operations must never race on the same object.

The class checks inGate/onThread to reject the owner's gate/work-loop context
for client calls. Those checks do not prove that an arbitrary other caller is
a sleepable thread: interrupt exclusion and operation lifetime are additional
controller obligations. No such controlling service is connected yet.

## Mapping, copying and bounds

The source requires IOMapper::copyMapperForDevice on the supplied PCI provider;
failure has no physical-address, global-mapper or bypass fallback. It allocates
wired kernel buffer memory, zeros it, prepares its descriptor, attaches an
IODMACommand without auto-prepare, then explicitly prepares a 32-bit kMapped
command with that mapper. The device receives addresses only through
gen32IOVMSegments. CPU addresses and raw physical addresses are never published.

The allocation is bounded to 64 KiB, one to four segments, and power-of-two
bus alignment between 4 and 4096. An extra temporary segment slot detects
overflow of the requested scatter limit. Every segment must be nonzero,
aligned, below the requested length limit and entirely below 4 GiB; generated
offset and accumulated lengths must cover the entire requested transfer.
These are resource limits, not claims that every AR9565 queue accepts them:
TX still requires its codec's 12-bit per-buffer length and RX queue geometry
needs its own validation before a pointer is programmed.

TX writes update the original descriptor and invalidate readiness. Explicit
OUT synchronization then updates any command bounce storage before publication.
RX reads synchronize IN only after completed-transfer retirement and copy from
the original descriptor. Client copy inputs/outputs are required to be disjoint
from the buffer's live CPU DMA storage and owner object. RX output zeroing only
occurs **after** those alias checks; otherwise a forged output could erase DMA
data or live mapping ownership before synchronization. Likewise a gated publish
rejects an output reference into the buffer object before clearing its layout.
After validated arguments, RX reads clear caller output before synchronization
and again after a short copy, so a failed operation cannot leave a stale or
partial packet in that output. Caller lengths must come from verified RX status,
never from capacity or an untrusted frame header. No CPU pointer escapes.
Apple's [synchronize contract](https://developer.apple.com/documentation/kernel/iodmacommand/1547719-synchronize)
defines those IN/OUT copy directions; [complete](https://developer.apple.com/documentation/kernel/iodmacommand/1811081-complete)
requires matching preparation and transfer completion. These API descriptions
are not a substitute for exact-build ABI and physical DMA validation.

The class intentionally does not expose a perpetually active descriptor/status
ring: whole-buffer bounce synchronization while hardware modifies a ring is a
different contract. A coherent ring allocation, memory/doorbell barriers,
actual queues, interrupts and completion validation remain required. Packet
buffers alone do not implement any of those or authorize transmission.

## Cleanup and evidence limits

Normal client release pairs DMA-command complete/clear, descriptor complete,
then releases command/buffer/mapper/provider/work-loop resources. It refuses
DeviceOwned buffers. A failed completion/clear is quarantined as CleanupFailed;
it does not retry a possibly already consumed prepare/complete pair. Unexpected
destruction retains resources and logs incomplete teardown rather than freeing
a potential DMA target or running blocking cleanup in an unknown context.
This deliberately leaks resources on invalid/error teardown; a production
controller needs a retained quarantine registry and verified recovery policy.
It is not a claim of a complete teardown implementation.

`docs/evidence/NATIVE-DMA-API-CANDIDATES.json` records the pinned header hashes
and static kernel nlist candidates from the exact KDK. The factories, mapper,
DMA methods and support names used by this source occur there. The abstract
IOMemoryDescriptor prepare/complete base names have no candidate in that search;
calls use virtual dispatch through the actual descriptor. Missing base names
do not establish missing functionality. All relevant virtual slots, effective
KPI eligibility and actual compiled imports remain unverified. No callable
addresses or Apple implementation code are copied into this source.

Enabling the macro alone is not supported: native PCI/power ownership, the
controller's two-phase worker/gate lifecycle, authoritative TX safety, native
Wi-Fi and hardware validation are still missing. After separate authorization,
build/import checks and tests must cover allocation/copy/sync failures,
mapper absence, segment overflow, sleep during allocation, distinct-buffer and
stale-submission tokens, RX quiesce without completion, and quiescence failures.
None has been executed.
