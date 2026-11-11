# Contributing to SimpleATH

SimpleATH is experimental systems software. Propose bounded, auditable changes
that preserve source provenance, existing third-party notices and explicit
failure behavior. Do not claim a driver is verified unless hardware evidence
has been recorded and independently reviewed.

## Development practices

* Use English for source documentation and commit messages.
* Keep each commit scoped and self-contained; follow `type(scope): summary`
  (maximum 72 characters), a descriptive body (at least 80 characters), and
  `Signed-off-by: name <mail>`
  for commits authored and signed off by the maintainer. Other contributors
  must sign off with their **own** valid identity, not impersonate the
  maintainer.
* Preserve all existing third-party authors, texts, hashes and source links.
  New code must have a `Boundary-Contract` header and a file provenance record.
* Run the offline Python and public-contract checks. On macOS, also run the
  strict native validation workflow when tools are available.
* Document code changes and tests honestly; omitted checks must be disclosed.
* Keep runtime artifacts, downloaded SDKs, `.cache/` and credentials out of Git.

The file-level SPDX declarations govern each file.
`LicenseRef-SimpleBCM-All-Rights-Reserved` denotes
unresolved licensing and is **not** authorization to redistribute third-party
material under MIT; legal clarification or replacement may be necessary.
