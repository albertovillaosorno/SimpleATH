#!/usr/bin/env python3
# Copyright:
#   - Copyright © 2026 Alberto Villa Osorno
# SPDX-License-Identifier:
#   - MIT
# Confidential:
#   - false
# License-File:
#   - LICENSE-MIT
# Provenance:
#   - SimpleATH original; independently developed or locally authored
#
# Boundary-Contract:
# - Owns:
#   - Host-side tooling for bootstrap sdk.
# - Must-Not:
#   - Read unrelated user files, hide failures, or bypass explicit tool inputs.
# - Allows:
#   - Inputs: explicit command-line, repository, or fixture inputs.
#   - Outputs: deterministic reports, generated artifacts, or error codes.
#   - Side effects: bounded local source-analysis or developer-command activity.
# - Split-When:
#   - A separate protocol stage needs independent validation and ownership.
# - Merge-When:
#   - The caller directly owns this narrow contract without reuse.
# - Summary:
#   - Host-side tooling for bootstrap sdk.
# - Description:
#   - Implements or verifies the bootstrap_sdk source boundary.
# - Usage:
#   - Invoked by developers or CI with an explicit checkout context.
# - Defaults:
#   - Missing evidence, invalid input, or unsupported states fail closed.
#
# Module: Host-side tooling for bootstrap sdk.

# Copyright © 2026 SimpleATH contributors.
"""Fetch the pinned SDK through the canonical reference downloader.

This SDK-only entrypoint remains the CI prerequisite. It neither downloads the
Linux tree nor runs upstream code, a compiler or a kernel build.
"""

from pathlib import Path
import sys

if __package__:
    from tools.references.download import REPOSITORIES
    from tools.references.download import download
    from tools.references.download import seed_ledger
    from tools.references.download import update_ledger
else:
    from references.download import REPOSITORIES
    from references.download import download
    from references.download import seed_ledger
    from references.download import update_ledger

MAC_KERNEL_SDK = "MacKernelSDK"
ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / ".references" / MAC_KERNEL_SDK
SDK = next(
    repository
    for repository in REPOSITORIES
    if repository.name == MAC_KERNEL_SDK
)
REVISION = SDK.revision


def main() -> None:
    """Acquire/verify SDK bytes and preserve the sole reference ledger."""
    DEST.parent.mkdir(parents=True, exist_ok=True)
    seed_ledger(DEST.parent)
    records = download(SDK, DEST.parent)
    added = update_ledger(DEST.parent / "ledger.jsonl", records)
    _ = sys.stdout.write(
        f"{MAC_KERNEL_SDK} verified: {REVISION}; {added} new ledger entries\n"
    )


if __name__ == "__main__":
    main()
