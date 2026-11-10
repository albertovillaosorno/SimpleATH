# Offline host tests

Add a regression only when material behavior or an error path benefits from
execution. Use synthetic frames, EEPROM bytes and fake transports. Tests must
not open PCI, enable RF, access EFI/SSD, install software, download data or
build/load a kext. A host pass does not verify Tahoe's kernel ABI or Wi-Fi.

Run the existing validator (host tests are enabled by default):

```sh
python3 -B tools/validate.py
```

Every invocation checks all repository source files with Clang-Format,
Clang-Tidy, Ruff and BasedPyright, plus all available offline host tests.
The report is always structured JSON; only failed/skipped rows are included,
but its summary counts every check. The validator locks its shared cache and
report across concurrent runs. Positional file arguments are ignored, and
`--no-tidy`, `--no-tests`, and `--no-json` are rejected. `--no-cache`
forces all tools to run again and refreshes the full-repository cache.

```sh
python3 -B tools/validate.py --no-cache
```

Validation uses the same strict macOS-compatible rules on every host.
Missing Apple SDK/KDK headers are Clang-Tidy **failures**, not skips. The
former `--linux` skip flag is deliberately unsupported. On Fedora, install the
pinned MacKernelSDK and refresh `compile_commands.json` before validating:

```sh
python3 -B tools/bootstrap_sdk.py
python3 -B tools/generate_compile_commands.py
python3 -B tools/validate.py --no-cache
```

The local kernel-header dependency does not provide proprietary Tahoe wireless
interfaces or userspace CoreWLAN. Any native parse failures stay visible.
Reports use a single `validation_mode: macos` label regardless of host OS.

Python tests use standard-library unittest: name modules `test_*.py` and add
`__init__.py` to test packages. The runner launches each module's discovered
suite in an isolated Python process. Zero tests, unittest skips and unavailable
requested tooling are reported as skipped and cause a nonzero validator exit.
Test failures propagate. Python optimization environment variables are ignored
so test assertions cannot disappear accidentally.

Native tests are `test_*.cpp` or `test_*.mm`, each providing `int main()`.
The installed clang++ compiles a standalone host executable with C++17,
warnings enabled and `src/` as an include path, then runs it. Nonzero compile
or runtime status fails the test. `.mm` selects Clang's Objective-C++ frontend;
the included test exercises `@encode` plus the portable RX parser. It does
not emulate IOKit, Foundation, AirPort or Darwin kernel objects. A test needing
unavailable platform libraries must report that limitation, never a fake pass.

For extra translation units, place a companion with the same stem and the
`.sources` suffix, containing repository-relative source paths, one per line:

```text
src/hardware/Ar9565Core.cpp
```

Blank lines and `#` comments are allowed. Source paths are passed as separate
arguments; no shell, arbitrary flags, build system or downloaded framework is
used. Escaping paths are rejected. Temporary executables are deleted after
execution. Timeouts terminate/reap the child process group; diagnostic output
is bounded. Test outcomes are never cached. Existing lint caching remains.

The validator requires the project's Python 3.14 tool environment. Keep it
Ruff/BasedPyright clean using the root configurations. A targeted green report
does not clear the separate repository-wide validator-findings TODO.

Implementation references: [unittest discovery](https://docs.python.org/3.14/library/unittest.html#test-discovery),
[subprocess control](https://docs.python.org/3.14/library/subprocess.html),
and [Clang driver modes](https://clang.llvm.org/docs/CommandGuide/clang.html).
