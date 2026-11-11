# Linux reference ledger

The owner requested a JSONL ledger to track the Linux source migration.
`.references/ledger.jsonl` inventories the files under `.references/linux/`
and records source provenance separately from implementation progress. Preserve
the
reference tree until the AR9565 retirement TODO is complete. The owner's
later instruction requests deletion after that source milestone; existing
inline notices and THIRD_PARTY_NOTICES.md suffice without extra archives.

The initial snapshot contains 419 local reference files: 16 have documented
partial implementation scopes and 403 have no recorded implementation
assessment. None is marked complete. The local `.references/linux/` tree is
excluded from Git by the existing ignore rule; this ledger records its actual
file
contents by hash without changing that rule or adding the tree to Git.

Linux schema-1 lines are complete objects for a `source` path relative to
`.references/` (for example `linux/drivers/...`) and exact `sha256`. The initial
inventory covers the reference files present at creation. Append another
complete record when reviewing or
porting that source; the last record for a path is current. Readers must
compare its hash with the current reference file: a mismatch makes the
record stale, not automatically applicable to the new version. Record a
new source version explicitly and reassess its implementation scopes.

`usage` is `recorded` or `not_recorded`. The latter means that this ledger
has no evidence of use; it does not assert that nobody has read the file.
`implementation` is `not_assessed`, `reference_only`, `partial`,
`complete_for_required_scope`, or `not_required_for_target`. Never infer
completion from a filename, an include, a successful build, boot, or the
presence of generated data.

`scopes` describes actual algorithms, constants or data carried over.
`destinations` identifies their source-code evidence. `remaining` lists
known source work and limits of the claim. Completion applies only to
the explicitly recorded required scope; unrelated chipsets and Linux
subsystems need not be reproduced. Initial generated-table records
claim selected data extraction only. They do not claim radio bring-up.
`baseline_commit` identifies the committed source inspected for that
record; future updates may reference their implementation commit instead.

Retirement also requires an `applicability` decision: `required`,
`supporting`, or `out_of_scope`, with a `rationale` tied to this target.
Absence of these fields means unassessed. `not_required_for_target` needs
an explicit explanation; it is not an implementation-completion claim.
Do not port unrelated Linux subsystems just to exhaust the inventory.

`license.spdx_expression` records an SPDX line when present, without
relicensing the source. A missing expression does not imply permission.
`license.review` distinguishes an observed permissive notice from a file
whose specific licensing still needs review before derivation. Consult
the original file and retain its applicable notices in derived work.

Append complete lines and inspect the diff before committing. Never
interleave two writers' appends; reread the file after concurrent edits.
If an interrupted write leaves an incomplete final line, preserve the
previous complete records and repair that tail before committing. Git
provides the reviewed history; JSONL is already the append log, so no
additional WAL, database or orchestration tool is introduced.

All implementation states describe source evidence only. They authorize
no kext build, installation, transmission or hardware experiment. The owner's
separate authorization permits necessary offline host tests under tests/
through tools/validate.py --tests; a ledger status adds no further permission.
Delete the local Linux tree only after all conditions in the dedicated
`linux-reference-retirement` TODO hold. Keep this existing ledger and source
notices; no additional archive, mirror or preservation tooling is required.

## One ledger for all references

The owner consolidated Linux port history and upstream acquisition into
`.references/ledger.jsonl`. Do not create a second ledger. Existing schema-1
Linux records retain their original source identities and full history;
latest `source` wins. Their verified `revision` and `upstream_path` allow the
reference downloader to reconstruct missing Linux files without changing
implementation assessments. Schema `simpleath.reference.v1` records describe
other upstream sources, including MacKernelSDK: identity is repository,
revision and path. `cache_path` is relative to `.references/`. Keep download
status separate from actual implementation/reuse assessments. Receipt JSON
files are disposable cache verification metadata, not additional ledgers.
