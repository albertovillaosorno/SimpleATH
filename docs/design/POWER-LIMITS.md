# AR9565 power candidates and CTL interpretation — source only

`Ar9565Power.*` is staged in the Xcode Sources phase. Its portable numerical
EEPROM target/CTL interpretation and separately gated chain-zero OLPC and
per-rate TPC register programming are exercised by synthetic offline host
tests, not by a physical device. These source-only MMIO stages are **not called
by the native PCI owner**; the module does not approve a regulatory domain,
validate live board calibration, enable a transmitter, or establish a legal
measured transmit power.

## Calculations implemented

The input must be a reconstructed version-2 little-endian image passing the
existing structural board summary (MAC, single-chain mask and 2 GHz support),
then `selectBoardGainProfiles` structural admission: three in-band strictly
increasing 2 GHz calibration-pier bins, non-template permanent MAC and supported
AR9565 gain indices. The direct power calculator rejects these invalid boards
as `InvalidBoard` even if the independent CTL and target curves are valid; it
cannot bypass discovery's board rejection and publish seemingly usable limits.
Synthetic tests corrupt a pier bin or substitute the pinned dictionary MAC
and check that previously populated output is cleared.
This is not proof that the image came from the Dell or contains usable factory
calibration. No template alone can satisfy physical-board verification.

The module reads these packed AR9300-format 2 GHz fields without native casts.
The current parser holds typed fixed-size table layouts and performs bounds-
checked reads against the entire restored image; caller-defined CTL mode/group
and the table's frequency/bin offsets are kept as distinct inputs:

| Target group | Frequency-bin offset | Power offset | Piers | Rate groups |
| --- | ---: | ---: | ---: | ---: |
| CCK | 195 | 206 | 2 | 4 |
| OFDM | 197 | 214 | 3 | 4 |
| HT20 | 200 | 226 | 3 | 14 |
| HT40 | 203 | 268 | 3 | 14 |

Frequency bins are 2300 MHz + bin. The unused 0xff sentinel must trail valid,
strictly increasing piers. Power values must fit 0..63 half-dBm units.
Interpolation uses ath9k's signed-integer rounding, including negative slopes,
and its nearest endpoint outside the target-pier range. Endpoints extend a
*target curve*, not channel/regulatory permission.

CTL indexes start at 310, four frequency edges per row at 322, and four packed
edge-power/flag bytes per row at 370. Specific groups use the first matching
mode/index as upstream; explicit group 0xe0 takes the minimum across matching
modes. Exact edge hits use its lower six power bits. Interior frequencies use
the preceding edge only when its in-band flags are nonzero. Missing groups,
coverage, empty rows and non-monotonic edges return errors. Pinned
ath9k AR9300 2 GHz dictionaries also contain trailing zero-filled CTL bins,
although upstream's generic unused-bin sentinel is 0xff. This stricter source
parser treats either 0x00 or 0xff as **trailing padding only**: a later
nonempty edge is malformed, and neither terminator supplies channel coverage.
Synthetic tests check valid mixed padding and reject interior/empty edges.
The 12-entry CTL-index table must also have only trailing zero padding: a
nonzero index after the first zero is a malformed table, even if an earlier
index could satisfy the requested mode. Such a chain returns
`InvalidCtlIndexes` without exposing stale power candidates.

There are two deliberate fail-closed departures from upstream's permissive
fallbacks: uncovered CTL frequencies do not acquire MAX_RATE_POWER, and a
zero edge cap is not upgraded to 60. These departures must be reviewed against
real board dumps before hardware integration. A numeric zero half-dBm cap is
0 dBm, **not an RF mute**. Negative ceilings return UnsupportedPowerLimit
instead of wrapping or silently promoting the limit to zero.

Caller-provided conducted and EIRP ceilings are intersected with EEPROM
targets and CTL. Positive antenna gain is subtracted from the EIRP ceiling
before the conducted comparison. A negative raw antenna gain never increases
power. This assumes no credited cable loss. The antenna value still requires
physical-board validation; the caller's country/OS authority is not supplied
by this module and must cover occupied bandwidth and both HT40 subchannels.

HT40 geometry requires primary and secondary channels 20 MHz apart. As in
ath9k, its target curve is interpolated at the control frequency and its CTL
is looked up at the synth center. EEPROM HT20/HT40-disable flags are honored.
Channel 14 has only CCK candidates and cannot have an HT40 secondary.
The rate selector handles CCK long/short preamble, OFDM and single-stream
MCS0..7; multi-stream and unknown codes fail. Because the selector accepts a
caller-owned structure, it also verifies secondary-channel geometry, synth
center, HT mode consistency and that selected values are within the 0..63
hardware field range and the supplied conducted ceiling. A manually forged
PowerCandidates structure still cannot confer regulatory or hardware authority.

The EEPROM image, channel and ceiling inputs must not overlap the power
candidate output, and the rate selector output must be disjoint from the
candidate. Likewise, board-summary output cannot overlap the EEPROM image,
and TX/RX gain outputs cannot overlap the board or each other. These invalid
aliases return InvalidArgument before modifying either output or input;
ordinary failed power calculations still clear stale output.

## Modal open-loop TX inputs — 2026-11-10

The packed AR9300 board input path now separately extracts `pwrTableOffset`
(signed dB), signed 2-GHz `tempSlope`/`voltSlope`, and the raw
`featureEnable` byte from an admitted reconstructed image. It copies these
into `PowerCandidates::txModal` next to the interpolated per-channel
reference correction, voltage and temperature. This preserves the raw
source inputs used by Linux ath9k's `ar9003_hw_power_control_override`
without inventing live temperature, additional compensation or hardware
settings in this parsing step. The independent gated register stage is
documented below. Invalid structural board admission blocks the output
and clears stale values. The synthetic C++14 and C++17 sanitizer regressions
exercise
signed values and the power-candidate handoff; focused strict Tidy passes.

The parser alone is **not** a hardware transmitter power-control
implementation, a successful radio calibration, or permission to transmit.
The native
serialized owner still has to establish live board provenance, *apply and
verify* TPC registers on physical hardware and enforce country/antenna/RF gates.

## Hardware TX rate-bank source stage — 2026-11-10

`makeAr9565TxRateRegisters` packs a single-chain candidate into all 12 AR9003
`AR_PHY_POWER_TX_RATE(n)` words, including mixed HT20/HT40 groups, CCK preamble
minima and ACK/CTS power. Malformed geometry, an over-ceiling target and stale
channel-calibration metadata fail closed. Absent rate modes get numeric zero,
**not RF mute**. Synthetic vectors test CCK minima, HT40 grouping and errors.

`programAr9565TxRateRegisters` is a separately gated MMIO source stage. It
requires explicit full TX authorization, plus a synchronous native owner-epoch
callback that independently verifies D0, the physical board, applied TPC/
thermal compensation, country and antenna policy, RF kill, coexistence and
quiesced MAC/queues/automatic responses. With permission it disables forced
gain, programs 12 rate registers, and updates only AR_TPC ACK/CTS power bits,
retaining unrelated bits. Every write is read back, and partial/ambiguous
writes or revoked ownership require a reset. Fake-MMIO host tests cover
success, write/read failure, readback mismatch and owner revocation. No live
caller invokes this source; it **never enables the transmitter**, MAC, EDMA,
automatic ACK or TX-ready flags. No hardware has been accessed by these tests.

## Open-loop and ordered TX power programming — 2026-11-10

`programAr9565TxOpenLoopCalibration` adapts the pinned ath9k
`ar9003_hw_power_control_override` chain-zero path using the structurally
admitted 2-GHz channel calibration and board modal values. It updates four
AR9565 PHY registers: gain delta (`TPC_11_B0`), open-loop error-estimator
mode (`TPC_6_B0`), signed thermal slope (`TPC_19`) and calibration-temperature
reference (`TPC_18`). It only modifies the relevant bit fields, verifies each
posted write against a readback, checks live ownership before every access,
and requires reset after a failed or uncertain write. This is **not** a live
thermal or voltage tracking system, and its inputs are factory-data fields,
not measured calibrated transmitter power.

`programAr9565TransmitPower` orders this OLPC stage before the existing
12-word rate/TPC bank under a single immutable candidate, authorization and
PCI-backend snapshot. A full BAR-length preflight rejects a device window too
short for the *later* rate bank before OLPC can write anything. A second-stage
failure retains the reset requirement from earlier OLPC writes, even if the
later failure occurs before the bank's first write. Synthetic C++14/C++17
ASan+UBSan fixtures verify positive register fields, protection against caller
mutation during MMIO callbacks, invalid BAR, revoked permission, readback
mismatch, partial failure and cross-stage reset obligations. Direct strict
Clang-Tidy and formatting checks pass for the source and test.

These source stages have no native PCI owner caller and grant neither TX
readiness nor the country, antenna, MCI/coexistence, calibrated descriptor
power or automatic-response safety authority required for actual transmission.

## What remains before any transmission

PowerCandidates contains **half-dBm candidate limits**, not descriptor power
indexes. Do not assign these directly to TxRate::powerIndex or mark any
TxSafetyPolicy readiness boolean from arithmetic success. Actual factory
calibration verification and applied compensation, PAPRD/backoff, MCI/
coexistence caps, descriptor power-index mapping, native MMIO integration,
autonomous ACK/CTS safety, live power readback and physical measurements remain
unimplemented/unverified. The staged rate-bank source does not authorize TX.

The verified country/OS/board domain intersection and live RF-kill/antenna
state remain missing. Choosing ctlGroup or entering a country string does
not create that authority. The passive service remains unchanged and the
hardware core still cannot transmit. Native PCI/IO80211, actual DMA/interrupt
queues and physical validation are also open blockers.

The source retains Atheros permission/copyright notices and pins the local
ar9003_eeprom.c/.h, eeprom.h and common-init.c references by SHA-256. No Linux
object or GPL-only implementation is linked/copied into this module.

The focused `tests/test_power_candidates.cpp` host fixture passes under both
C++14 and C++17 with AddressSanitizer and UndefinedBehaviorSanitizer. Direct
strict Clang-Tidy reports zero diagnostics for `Ar9565Power.cpp`; it also
passes Clang formatting and diff checks. These synthetic checks exercise
rate-group selection, CCK floor semantics, CTL padding and missing coverage,
board identity and pier rejection, HT40 geometry and channel calibration.
They do not replace a differential ath9k target/CTL vector audit or any
physical TX-power calibration, regulatory approval, native register readback
or physical measurement. Those remain required before any transmission.
