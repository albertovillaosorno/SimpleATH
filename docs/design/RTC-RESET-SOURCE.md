# AR9565 RTC and MAC reset: source-only contract

**Status:** Portable, inactive reset-source candidate. Not wired to the
passive kext, not compiled, and not physically verified. In particular,
`RtcPowerBackend` is a contract, **not** a real native MMIO writer.

## Pinned Linux reference and scope

The local `linux/drivers/net/wireless/ath/ath9k/` reference files are
preserved, with SHA-256 identities recorded in `linux-port-ledger.jsonl`:

- `hw.c`: first-PCI-attach WA snapshot (near line 605); MAC warm/cold
  reset, power-on and awake transitions (near lines 1351–1508, 2170–2210).
- `hw.h`: AR9565 device identity and family definitions.
- `reg.h`: AR_WA, AR_RC, interrupt timeout bits and RTC offsets/masks.

The portable implementation in `src/hardware/Ar9565RtcPower.*` includes
only the non-SoC AR9003 RTC control sequence and its AR9565-specific
WA bit 22. It preserves the initial AR_WA snapshot across sleep **only**
for the same retained PCI provider. A different power/ownership epoch
invalidates completed bootstrap, even if the provider is unchanged.
It does not import Linux objects, implement Linux's whole power subsystem,
or enable a network interface.

## Required external invariants

The future caller must supply a uniquely identified physical AR9565 PCI
provider, actual D0 and exclusive ownership, a stable mapped BAR and an
unreused nonzero power/ownership epoch. It must serialize all callbacks on
one work loop, with no reentry or hard interrupt context. Interrupts, MAC
automatic replies, DMA, RX and TX must already be quiesced before reset.
A provider token MUST NOT be reused for a different PCI function.
The caller's context and status storage must be disjoint from each other,
from the backend and from the identity. The callback context must also live
outside both outputs; a context pointer into either is explicitly rejected,
and callers must keep its entire backing allocation disjoint. These aliases
fail before zeroing status or invoking any callback, leaving both outputs
untouched. Other failures still report through the status object.

`write32` must order and drain *device* posted writes before reporting
success. A CPU fence alone does not establish delivery. `nowMicros` is
monotonic, and `delayMicros` must take at least the requested interval
on that same clock. The transition checks observed elapsed time after
every delay; a short delay is an explicit failure, not a successful
reset pulse. Callback latency also counts toward a 250 ms global budget.
Every access revalidates the ownership epoch and BAR bounds. Callback
routing, provider token and owner epoch are copied once after alias preflight;
retained pointers into the caller's original callback table cannot retarget
an in-flight transition. This does not replace the required serialized owner
and retained callback context. A callback that cannot prove its contract must
return failure; this source does not attempt an unsafe device-register
fallback or guess a D0 state.

## Supported sequence and fail-closed results

A fresh, zero-initialized context first validates PCI identity and type-2
SREV and reads AR_WA before the initial reset. Incoherent reused contexts
are rejected before any register access. The bootstrap path applies the WA wake
bits, forces wake, toggles RTC_RESET, polls RTC_STATUS for ON, issues a
warm MAC reset, then sets the AR9565 WA workaround bit. Only successful
bootstrap authorizes later EnsureAwake/WarmReset/ColdReset operations
**in that ownership epoch only**. Readiness is committed after the final
RTC status check, MCI callback and a separate ownership/clock gate, never
merely after the last write. A synthetic callback regression revokes
ownership immediately after the final status-read gate; the transition now
returns `AccessRevoked` and clears bootstrap readiness rather than publishing
success. Revocation during the initial ownership check or inside the first
clock callback likewise retires a previously successful bootstrap *without*
requiring any MMIO writes. The preflight revocation and every later
active-operation failure discard the ready epoch; a subsequent reset must
bootstrap anew even if a faulty provider reports the old owner token/epoch
after a power interruption. The original workaround
capture remains tied to the same provider; none of this verifies native PCI
ownership or makes a stale native epoch acceptable. This is not proof that a
real provider can prevent an unguarded D0 transition outside a serialized
owner transaction.

Warm/cold MAC reset polls AR_RTC_RC, conditionally handles host-interface
sync timeouts, and uses 50 us reset assertion for this AR9003 variant.
The source explicitly excludes AR9330 external reset and AR9300/AR9580
DMA-halt workarounds, which belong to different silicon. Optional MCI
callbacks must be supplied by a proven coexistence owner if enabled.

The transition does **not** program PLL, PHY, RF, regulatory power,
antenna, RF-kill, sleep policy, keys, interrupt routes, DMA rings or
transmit permissions. Success means only that its bounded RTC operations
were reported complete by the callback contract; it does not make the
radio ready. If any reset write may have reached the device, status
marks board state invalidated and the caller must discard affected
channel, calibration, key and queue assumptions. It must not attempt to
restore unknown hardware state or free possibly hardware-owned buffers.

## Remaining source work

There is no verified native active-register backend, PCI D0 transition
or owner work-loop integration. The power/epoch contract, posted-write
flush, MCI handoff and MMIO ordering need a source-level native adapter
and independent exact-Tahoe ABI review. Hardware state after loss of
D0, provider termination, timeout or reset failure is deliberately
unknown. No source claim here substitutes for the final, owner-authorized
physical verification stage.
