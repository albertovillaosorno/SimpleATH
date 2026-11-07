# Jig compatibility assessment — optional, not an active gate

Assessment date: 2026-11-06.

The locally installed Jig 26.3.0 distribution was inspected and its
standard (not --full, no test suites) Jig check tried with a separate
A10 Git worktree. The attempted 24-file schema-21 configuration was
generated from already present local repository policies, without
downloading lint tools or compiling any kext.

**Decision: do not activate Jig for SimpleATH in this generation.**

The installed Jig source at
src/repository-governance/rules/domain/scalability/taxonomy/layout.rs
hardcodes BOTH mandatory exact routes:

- src/<domain>/<function>/<kind>/<part>
- tools/<function>/<kind>/<part>

Changing architecture.toml to an empty dependency graph does not
disable this rule. In the Jig source
src/repository-model/schema/contract/configuration/portability.rs,
RuleConfig::validate_invariants rejects both all_registered = false
and allow_disable = true. Thus a non-hexagonal SimpleATH cannot pass
the full Jig check using the installed release without relocating
the entire source tree or changing Jig's code.

The source-level inspection found that the policy check would also
reject thousands of preexisting long C++/Python lines and historic
commit-message styles. Altering kernel ABI sources, file layout and
Git history merely to display a green status would be unsafe and
misleading. The Jig check was RED; do not represent it as passing.

## Current code-quality policy

Continue using the checked-in root .clang-format, .clang-tidy,
.editorconfig, ruff.toml, pyrightconfig.json, and
msvc-cpp.editorconfig with the existing installed executables.
Do not download replacements. Keep the native Xcode build and
on-device tests gated by explicit owner authorization.

To reconsider Jig later, require an upstream release with a
documented, supported opt-out for canonical/hexagonal routes and
compatible incremental rule scoping. Audit that mechanism before
committing a .jig/ policy or adding Git hooks. A successful Jig
doctor is not equivalent to full Jig validation nor evidence
of a bootable or functioning Wi-Fi driver.
