# AR9565 active EEPROM/OTP read protocol — source only

`src/hardware/Ar9565NvmReader.*` stages the ath9k PCI EEPROM and AR9003 OTP
read protocols. The translation unit is in the SimpleATH Xcode target, but
has not been compiled, tested or connected to a native PCI owner. No NVM
transaction or physical dump has been acquired by this work.

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
  an all-ones second read, absent/protected status, or a return to BUSY; the
  latter is reported as `UnstableStatus`. This follows ath_pci_eeprom_read;
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
  bounds, not a measurement of physical storage capacity. Source/origin
  selection remains explicit and does not silently switch on errors.
- Reject overlapping destination, status, backend and identity storage
  before initializing diagnostics or clearing capture bytes; an alias error
  is reported by the return value without mutating aliased storage. Wipe a
  valid, disjoint destination span after acquisition failure and leave
  captureComplete false. A partial word count is diagnostic only.

No bus-master enabling, interrupt, DMA, RF write, EEPROM/OTP write or TX API
exists in this reader. Its ordinary MMIO reads still have device side effects
and require separately authorized hardware validation.

## Remaining integration and evidence

The verified Tahoe PCI/power adapter, source/origin discovery policy and
hardware comparison are still missing. An EEPROM-absent indication must not
be treated as proof that AR9565 OTP is absent; acquisition chooses the source
explicitly and OTP has its own protocol. A reconstructed image still needs
physical MAC/provenance checks and complete board calibration, antenna,
RF-kill, coexistence and regulatory/power validation before RF transmission.

The reader records upstream hashes and retains Atheros notices in its source.
The permissive Linux references are pci.c (ath_pci_eeprom_read), hw.c
(ath9k_hw_wait), reg.h and ar9003_eeprom.c/.h (OTP and normalization).
No Linux objects are linked into the kext.

After separate build/test authorization, validate register ordering, erased
data, busy/protection/absence, timeouts, disappearing ownership, clock faults,
BAR truncation, output invalidation and EEPROM/OTP byte order using an offline
backend. Actual NVM acquisition requires a separate explicitly authorized
hardware step with the verified owner. Neither check has been performed.
