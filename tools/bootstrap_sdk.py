#!/usr/bin/env python3
# Copyright © 2026 SimpleATH contributors.
"""Fetch the pinned SDK through the canonical reference downloader.

This SDK-only entrypoint remains the CI prerequisite. It neither downloads the
Linux tree nor runs upstream code, a compiler or a kernel build.
"""

from pathlib import Path

if __package__:
    from .references.download import REPOSITORIES
    from .references.download import download
    from .references.download import seed_ledger
    from .references.download import update_ledger
else:
    from references.download import REPOSITORIES
    from references.download import download
    from references.download import seed_ledger
    from references.download import update_ledger

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / ".references" / "MacKernelSDK"
SDK = next(
    repository
    for repository in REPOSITORIES
    if repository.name == "MacKernelSDK"
)
REVISION = SDK.revision


def main() -> None:
    """Acquire/verify SDK bytes and preserve the sole reference ledger."""
    DEST.parent.mkdir(parents=True, exist_ok=True)
    seed_ledger(DEST.parent)
    records = download(SDK, DEST.parent)
    added = update_ledger(DEST.parent / "ledger.jsonl", records)
    print(f"MacKernelSDK verified: {REVISION}; {added} new ledger entries")


if __name__ == "__main__":
    main()
