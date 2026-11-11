# SimpleATH contributor and automation guidance

Treat this repository as a public, experimental macOS kernel networking
project. Prioritize verifiable source changes and preserve fail-closed paths.
Read `README.md`, `TODO.md`, relevant `docs/design/` records, and the
licensing inventory before modifying driver code.

Do not claim physical verification from host-side tests, source inspection,
or builds alone. A source implementation is not a statement of device support.
Do not publish personal device information or diagnostic logs without review.
Do not auto-install kexts, change SIP, patch the system volume, or initiate
hardware experiments as part of routine source maintenance.

Keep all imported copyright notices and license terms. Newly authored code
uses `MIT`; third-party licensing takes precedence.
Every code file has a uniform `Boundary-Contract` header. Review
`docs/provenance/files.json` when adding, removing or replacing source files.
Run `python3 -B tools/public_contract.py all` and repository tests.

Commits follow the documented conventional-commit policy with descriptive
bodies and signed-off identity trailers. Rewrite and force push only during
an explicitly authorized, coordinated repository-wide maintenance operation.
Preserve existing work and use a force-with-lease safeguard when such a rewrite
is explicitly authorized. Routine work should use normal pull requests or
reviewed integrations where repository policy permits them.
