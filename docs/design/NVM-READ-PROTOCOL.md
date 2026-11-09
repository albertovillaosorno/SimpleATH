# AR9565 active EEPROM/OTP read protocol — source only

`src/hardware/Ar9565NvmReader.*` stages the ath9k PCI EEPROM and AR9003 OTP
read protocols. The translation unit is in the SimpleATH Xcode target and
has portable fake-I/O host regressions, but no authorized kext build or
native PCI owner connection. No physical NVM transaction or dump has been
acquired by this work.

This advances acquisition source, not hardware validation. The passive
IOService does not call it. Its three-register read-only bus cannot be used
for NVM triggers; that allowlist remains unchanged. The active reader needs
a separate capability supplied by the same verified exclusive PCI owner,
with retained context, D0, ordered BAR access and serialized power/stop.
Owner permission to edit source does not authorize invoking this capability.

## Protocol and bounds

- Check physical PCI 168c:0036 supplied by live configuration under the
  owner's session. Reject spoof-possible identity and unknown SREV. Read
  true SREV and require RTC ON before any NVM trigger. It does not reset/wake
  the device or make assumptions from registry properties.
- EEPROM: read trigger 0x2000 + wordIndex*4, wait on status/data at 0x4084
  for BUSY and PROT_ACCESS to clear, then read 0x4084 **again** and collect
  its lower 16 bits. Never consume the wait-loop sample as payload. Reject
  an all-ones second read, absent/protected status, or a return to BUSY or
  the separate BUSY_ACCESS bit; those unstable conditions report
  `UnstableStatus`. The wait mask follows ath_pci_eeprom_read;
  no EEPROM program/write command exists in this module.
- OTP: read trigger 0x14000 + wordIndex*4, wait for status at 0x15f18 with
  low three bits equal to 4, then collect data at 0x15f1c. Never write OTP.
- Validate aligned accesses against the assigned BAR length and recheck
  owner/D0 before each register access. Treat an all-ones SREV or status as
  a failed register transaction, not an unsupported silicon revision. Detect
  EEPROM absent-access status even if it arrives on the timeout poll; it
  never counts as a successful read. Erased NVM *data* words may be all ones
  and remain valid input to the reconstruction parser. A failed post-wait
  EEPROM data read also wipes the requested capture buffer.
- Bound each EEPROM word to 100 ms, each OTP word to 1 ms, the capture to
  2 s plus bounded callback overhead, and the overall poll count to 200,000.
  Poll every 10 microseconds. A stalled clock cannot produce an infinite
  polling loop. The backend must implement bounded callbacks and a monotonic
  clock; every consecutive observed clock sample is checked for regression,
  including samples around MMIO reads. Unobserved backward/forward excursions
  cannot be ruled out by sampling alone. The future owner must use
  thread/work-loop context, not a hard IRQ.
- Capture ascending-address bytes, extracting low bytes first from the
  little-endian EEPROM/OTP words. restoreEepromDump reverses each block into
  the descending-address stream expected by ath9k's compression format.
- Only the spans used by upstream AR9565 origin search are supported:
  up to 4096 EEPROM bytes and 1024 OTP bytes. Those are supported acquisition
  bounds, not a measurement of physical storage capacity.
- `discoverAr9565Nvm` now sequences five candidates in upstream order:
  EEPROM 0x3ff, 0xfff, 0x1ff; then OTP 0x3ff, 0x1ff. Each active read is
  bounded by `captureAr9565Nvm`, using caller-owned 4096-byte storage and
  1029-byte scratch. It checks a four-byte header at each origin, then
  captures one full image at the FIRST nonempty header. Thus at most five
  probe reads and one 2-second full capture can occur, each with a 2-second
  capture bound plus callback overhead. Only a blank/erased header or
  StorageAbsent during a probe can advance. A selected header forbids
  fallback on later checksum, layout, mid-capture absence, changed header
  or silicon revision, board identity, clock, transport or D0 failures.
- The discovered board snapshot retains actual source, origin and silicon
  together with a checksum-restored image and structurally checked summary.
  Reject pinned dictionary placeholder MACs, unknown gain profiles and
  malformed board identity rather than turning a template into a device.
  For a selected board, reject even a valid-checksum delta if the three
  2.4 GHz calibration pier bins are out of range, duplicated or out of order.
  The raw `summarizeBoardData` API can still report those invalid bins for
  diagnostics; it never grants RF authorization. Source-only commit 8701516
  adds an offline regression of this fail-closed board-selection check.
  Transient capture/scratch bytes are wiped even after success. Error
  cleanup clears the board selection; the future native owner must also
  invalidate it on reset, D0 loss, teardown and resume. A fresh owner/D0
  preflight is required after all software reconstruction and gain checks:
  successful capture alone is stale evidence if power disappears before
  publication. On failure, selection and buffers are wiped, and diagnostics
  report `CaptureFailed`/`SessionUnavailable`. The host regression forces
  D0 loss after the last read's clock check and before reconstruction ends.
  Neither the `valid` snapshot flag nor plausible calibration bins grants RF
  permission;
  `calibrationValidated` and `regulatoryAuthorized` remain false.
- `NvmBoardLease` retains the reconstructed image privately behind a
  strictly increasing owner epoch. A const board view is only borrowed under
  that owner's serialization gate for its current epoch. Failed acquisition,
  sleep, reset, teardown or D0 loss must invalidate the lease; old epochs
  cannot be replayed. Revocation during acquisition returns
  `OwnerEpochRevoked`, prevents publication, and defers erasure until the
  active operation completes. The future native
  owner must ALSO revoke hardware callbacks and drain the operation before
  releasing BAR mappings; the source-only epoch is not native ownership.
- Reject overlapping destination, status, backend and identity storage
  before initializing diagnostics or clearing capture bytes. Reject a
  backend context pointer that points into either writable output, too;
  its complete allocation must be kept disjoint by the caller because its
  size is opaque. An alias error is reported by the return value without
  mutating aliased storage. Wipe a
  valid, disjoint destination span after acquisition failure and leave
  captureComplete false. A partial word count is diagnostic only.

No bus-master enabling, interrupt, DMA, RF write, EEPROM/OTP write or TX API
exists in this reader. Its ordinary MMIO reads still have device side effects
and require separately authorized hardware validation.

## Remaining integration and evidence

The verified Tahoe PCI/power owner and actual acquisition activation remain
missing; offline source/origin discovery is not a live hardware path. An
EEPROM-absent indication is not proof that AR9565 OTP is absent. The
source search probes OTP through its separate protocol. A reconstructed
image still needs physical MAC/provenance checks, board calibration,
antenna/RF-kill/coexistence and regulatory/power validation before TX.

The reader records upstream hashes and retains Atheros notices in its source.
The permissive Linux references are pci.c (ath_pci_eeprom_read), hw.c
(ath9k_hw_wait), reg.h and ar9003_eeprom.c/.h (OTP and normalization).
No Linux objects are linked into the kext.

The authorized offline host tests now exercise synthetic register ordering,
post-ready BUSY_ACCESS, disappearing ownership, source/origin fallback,
checksum rejection, placeholder MAC rejection, epoch replay, revocation
and failure erasure. They do
not establish Tahoe kernel linkage, true register ordering, RF calibration
or physical NVM behavior. Native kext compilation and any device experiment
remain separately owner-authorized and have not been performed.
