# Repository source-analysis policies

All source-linter configuration lives in `.jig/lint/`:

* `src/.clang-tidy`: broad C++ safety, portability, modernize and naming checks.
  `HeaderFilterRegex: '(^|/)(src)/'`.
* `support/.clang-tidy`: lightweight bugprone and analyzer checks for `tools/`
  and `tests/`, without the source naming/modernize/readability policy.
  `HeaderFilterRegex: '(^|/)(tests|tools)/'`.
* `.clang-format`, `ruff.toml`, `src/pyrightconfig.json` and
`support/pyrightconfig.json`: language format and
  static analysis settings invoked with explicit `--style`/`--config`/`-p`.

Use `python3 -B tools/validate.py` to run the configured analysis after
`python3 -B tools/generate_compile_commands.py`. The root `.editorconfig`
remains at the root solely because editors discover it by parent traversal.
The tracked `compile_commands.json` uses repository-relative `directory` and
`file` values. SDK and toolchain paths use ignored `.cache/clang-tidy/`
symlinks generated locally. To configure another machine, set `SDKROOT`
on macOS and run `python3 -B tools/generate_compile_commands.py`. The
repository root is discovered from the generator, not hard-coded.
