# AR9565 power candidates and CTL interpretation — source only

`Ar9565Power.*` is staged in the Xcode Sources phase. It is uncompiled and
untested, with no device register or transmit path. This implements numerical
EEPROM target/CTL interpretation; it does not approve a regulatory domain,
validate board calibration, or establish a legal measured transmit power.

## Calculations implemented

The input must be a reconstructed version-2 little-endian image passing the
existing structural board summary (MAC, single-chain mask and 2 GHz support),
with three in-band strictly increasing 2 GHz calibration-pier bins. The direct
power calculator now rejects malformed pier geometry as `InvalidBoard` even if
the independent CTL and target curves are valid; it cannot bypass discovery's
board rejection and publish seemingly usable limits. Synthetic tests corrupt a
single pier bin and check that previously populated output is cleared.
This is not proof that the image came from the Dell or contains usable factory
calibration. No template alone can satisfy physical-board verification.

The module reads these packed AR9300-format 2 GHz fields without native casts:

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

## What remains before any transmission

PowerCandidates contains **half-dBm candidate limits**, not descriptor power
indexes. Do not assign these directly to TxRate::powerIndex or mark any
TxSafetyPolicy readiness boolean from arithmetic success. The hardware TPC
conversion, calibration corrections, PAPRD/backoff, MCI/coexistence caps,
per-rate power registers, autonomous ACK/CTS power and readback/measurement
remain unimplemented/unverified.

The verified country/OS/board domain intersection and live RF-kill/antenna
state remain missing. Choosing ctlGroup or entering a country string does
not create that authority. The passive service remains unchanged and the
hardware core still cannot transmit. Native PCI/IO80211, actual DMA/interrupt
queues and physical validation are also open blockers.

The source retains Atheros permission/copyright notices and pins the local
ar9003_eeprom.c/.h, eeprom.h and common-init.c references by SHA-256. No Linux
object or GPL-only implementation is linked/copied into this module.

After separate build/test authorization, compare target interpolation and
CTL/rate mapping with ath9k vectors, including signed rounding, sentinel/
duplicate/truncated curves, exact/interior/uncovered edges, zero caps, group
aggregation, EIRP/antenna subtraction, negative caps, HT-disable flags,
HT40+/HT40- and channel 14. None of these runtime checks has been executed.
Hardware approval additionally requires actual calibrated/programmed/measured
power evidence from the separately authorized device experiment.
