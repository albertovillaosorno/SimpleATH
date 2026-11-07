# AR9565 EEPROM source port

Status: uncompiled source only; no tests executed and no device EEPROM read.

`Ar9565Eeprom.*` reconstructs one normalized ath9k NVM block at a time. It
implements the four-byte compression header, 16-bit additive payload checksum,
uncompressed images and reference/delta block compression. It bounds every
record before copying and rejects missing bases/templates, unsupported
compression, bad checksums, truncated records, destination overlap and more
than 100 applied blocks. Errors are returned, not silently accepted. A caller
must discard the complete restore chain on any error. This is deliberately
stricter than upstream's default-image fallback and ignored delta failures.

The 1088-byte reconstructed image retains **all** board/calibration/target-power
and CTL bytes, including the unused 5 GHz area of the shared AR9300 format.
It does not claim that those bytes are valid calibration. No Linux templates
are currently supplied by the target; a reference-compressed block fails
unless a future caller supplies the exact pinned template. A template alone
cannot identify this board. No factory MAC, antenna or regulatory defaults
are substituted.

The parser consumes header/payload/checksum in descending NVM address order,
as produced by ath9k's ar9300_read_eeprom/read_otp. It does not read hardware,
discover a block chain, normalize EEPROM/OTP word streams, or implement the
OTP and EEPROM access/polling protocols. A storage reader still needs to
handle the 0x3ff/0xfff/0x1ff candidate origins, available storage bounds,
end-of-chain semantics and cumulative restoration in upstream order. The
AR9565 chain scanner also needs upstream's below-1024-byte compressed block
constraint; the block primitive independently supports full uncompressed
1088-byte images. Flash-format images require a separate validated path.

## Layout evidence

Offsets below were derived by static field-size inspection of the local
packed `ar9300_eeprom` definition, without compiling it:

| Field | Byte offset | Bytes |
| --- | ---: | ---: |
| Version, template, MAC, customer prefix | 0 | 28 |
| Base header (regDmn, chain masks, RF kill, gains, GPIO) | 28 | 25 |
| 2 GHz modal header (antenna, attenuation, timing, PAPRD) | 53 | 71 |
| Base extension 1 (including stored antenna diversity) | 124 | 14 |
| 2 GHz calibration frequency bins | 138 | 3 |
| 2 GHz per-chain/per-pier calibration | 141 | 54 |
| CCK/legacy/HT20/HT40 target frequency bins | 195 | 11 |
| CCK/legacy target power | 206 | 20 |
| HT20/HT40 target power | 226 | 84 |
| 2 GHz CTL indexes | 310 | 12 |
| 2 GHz CTL frequency bins | 322 | 48 |
| 2 GHz CTL edge power/flags | 370 | 48 |
| Shared-format 5 GHz modal/calibration/target/CTL area | 418 | 670 |

`summarizeBoardData` accepts only the version-2 little-endian format, a valid
unicast MAC and the AR9565 single-chain 0x11 mask with 2 GHz capability. These
are structural checks, not proof of board provenance. It extracts raw domains,
RF-silent GPIO/polarity, Bluetooth options, gain indexes, antenna controls/gain
and calibration frequency bins. Upstream overrides AR9565 EEP_ANT_DIV_CTL1 to
0xc9; both the stored value and this override are reported. Neither establishes
the Dell's physical antenna routing or the current RF-kill switch level.

`calibrationValidated` and `regulatoryAuthorized` remain false. This module
does not set the hardware core's EEPROM-valid state or create permission to
transmit. Calibration application, legal country intersection, CTL interpolation,
per-rate conducted/EIRP limits, RF-kill sampling, gain selection and coexistence
remain required. An OS locale or user-entered country alone is insufficient.

## Licensing and reference integrity

The algorithms and format come from the local Linux ath9k references. Their
permissive Atheros notice is retained in the new parser; new control code is
AGPL-3.0-only. The original Linux files and generated INI tables are unchanged.
Reference SHA-256 values are recorded in `Ar9565Eeprom.cpp`. No GPL-only Linux
implementation has been copied into the new parser.

## Verification still required after owner authorization

Compile the modules in the Xcode target. Exercise known upstream frames and
both EEPROM/OTP byte orders, six-bit template IDs, valid/invalid checksums,
zero-length deltas, odd/truncated records, boundary-exact writes, missing bases,
overlapping buffers and sequences with a late malformed block. Compare a
complete reconstructed board dump byte-for-byte with ath9k's restoration.
Do not replace these checks with a successful desktop boot or an invented
EEPROM result. Hardware acquisition and RF activity require separate consent.
