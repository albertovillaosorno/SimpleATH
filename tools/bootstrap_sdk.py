#!/usr/bin/env python3
# Copyright © 2026 SimpleATH contributors.

"""Fetch only the pinned kernel SDK required for the SimpleATH Xcode target.

Linux ath9k code and Broadcom payloads are not linked into the v1 bootstrap.
"""

from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import] - Shell-free pinned SDK Git operations only.
import sys

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / ".research" / "MacKernelSDK"
URL = "https://github.com/acidanthera/MacKernelSDK.git"
GIT = "git"
REVISION = "3f750085caa17ec3a7880f11c11bf4f48cd6a164"


def run(*args: str) -> None:
    """Run only Git using separate arguments and no shell interpolation.

    Raises:
        ValueError: The requested program is not Git.
        RuntimeError: Git is unavailable on the current path.

    """
    if not args or args[0] != GIT:
        message = "Only Git commands are supported"
        raise ValueError(message)
    executable = shutil.which("git")
    if executable is None:
        message = "Git executable is missing"
        raise RuntimeError(message)
    # Fixed Git subcommands and pinned SDK arguments; shell stays disabled.
    _ = subprocess.run([executable, *args[1:]], check=True)  # ruff: ignore[subprocess-without-shell-equals-true]


def _revision() -> str:
    executable = shutil.which("git")
    if executable is None:
        message = "Git executable is missing"
        raise RuntimeError(message)
    # Read-only fixed Git operation with a separate, non-shell path argument.
    return subprocess.check_output(  # ruff: ignore[subprocess-without-shell-equals-true]
        [executable, "-C", str(DEST), "rev-parse", "HEAD"], text=True
    ).strip()


def main() -> None:
    """Fetch the pinned SDK and reject an incomplete or mismatched checkout.

    Raises:
        RuntimeError: The SDK revision, headers or libraries are incorrect.

    """
    if not DEST.exists():
        DEST.parent.mkdir(exist_ok=True)
        run(
            "git",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            URL,
            str(DEST),
        )
        run(
            "git",
            "-C",
            str(DEST),
            "sparse-checkout",
            "set",
            "Headers",
            "Library/x86_64",
        )
        run("git", "-C", str(DEST), "checkout", "--detach", REVISION)
    actual = _revision()
    if actual != REVISION:
        message = "MacKernelSDK is not at the pinned revision"
        raise RuntimeError(message)
    if not (DEST / "Headers/IOKit/IOService.h").is_file():
        message = "MacKernelSDK headers missing"
        raise RuntimeError(message)
    if not (DEST / "Library/x86_64").is_dir():
        message = "MacKernelSDK x86_64 libraries missing"
        raise RuntimeError(message)
    _ = sys.stdout.write(f"MacKernelSDK verified: {actual}\n")


if __name__ == "__main__":
    main()
